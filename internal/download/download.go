// download.go
// =============================================================================
// GRUG: This is the download cave. Grug need Julia installer. Grug not open
// browser like caveman. Grug use HTTP sockets. Download the file. Show progress.
// Verify hash. Run installer. Wait for human to finish clicking buttons.
// Then check if dep is actually installed. No silent failures ever.
//
// Flow:
//   1. HTTP GET the URL with proper timeouts and User-Agent
//   2. Stream to temp file, show progress bar if Content-Length known
//   3. Optionally verify SHA-256 hash of downloaded file
//   4. Launch the downloaded installer (platform-aware: .exe, .msi, .dmg, .sh)
//   5. Wait for user to confirm install is done (Enter key)
//   6. Return — caller re-checks the dep
//
// GRUG: no browser. no xdg-open for the download itself. pure sockets.
// browser was a crutch. real downloader uses net/http like an adult.
//
// GRUG: retries are caller's job. this package does ONE attempt with clear
// error reporting. caller decides retry policy. separation of concerns.
//
// ---
// ACADEMIC: The download pipeline uses net/http.Client with explicit timeouts
// on the transport layer (TLS handshake, response headers, idle connection)
// rather than a single monolithic Client.Timeout. This prevents large downloads
// from being killed by a global deadline while still catching stalled connections.
//
// Progress reporting uses an io.TeeReader pattern: bytes stream from the HTTP
// response body through a counting writer into the destination file. The progress
// callback fires every N bytes (configurable) without buffering the entire
// response in memory. Peak memory usage is O(buffer_size), not O(file_size).
//
// Hash verification (optional) re-reads the downloaded file with SHA-256.
// We do NOT hash during download because a partial/corrupted download that
// fails mid-stream would produce a useless partial hash. Hashing the final
// file on disk is the ground truth — it's what the installer will actually run.
//
// Installer launch uses os/exec.Command with platform detection:
//   - Windows: direct exec for .exe/.msi, "msiexec /i" for .msi
//   - macOS: "open" for .dmg, direct exec for .pkg
//   - Linux: "sh" for .sh/.run, direct exec for .AppImage
// The installer runs as a child process. We do NOT wait for it to exit
// because GUI installers often spawn subprocesses and return immediately.
// Instead we prompt the user to press Enter when done, then the caller
// re-checks the dependency.
// =============================================================================

package download

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Result is what Download hands back. Caller gets the file path and size.
// HashMatch is only meaningful if ExpectedHash was provided.
type Result struct {
	FilePath  string // absolute path to downloaded file
	Size      int64  // bytes written
	SHA256    string // hex-encoded SHA-256 of downloaded file
	HashMatch bool   // true if ExpectedHash was provided and matched
}

// Options configures a single download operation.
// URL is required. Everything else has sane defaults.
type Options struct {
	URL          string // required — what to download
	DestDir      string // where to save. empty = os.TempDir()
	FileName     string // override filename. empty = derive from URL
	ExpectedHash string // hex-encoded SHA-256. empty = skip verification
	OnProgress   func(downloaded, total int64) // optional progress callback
}

// Download fetches a file over HTTP(S) and saves it to disk.
// Returns FATAL-prefixed errors on any failure. No silent partial downloads.
//
// The caller is responsible for cleanup of the downloaded file.
func Download(opts Options) (*Result, error) {
	if opts.URL == "" {
		return nil, fmt.Errorf("!!! FATAL: download URL is empty")
	}

	// ------------------------------------------------------------------
	// Build HTTP client with sane timeouts
	// GRUG: no global timeout — large files need time. but stalled
	// connections need to die fast. per-stage timeouts solve both.
	// ------------------------------------------------------------------
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second, // GRUG: TCP connect timeout. 30s is generous.
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		// GRUG: no global timeout. a 2GB Julia installer on slow wifi needs
		// more than 5 minutes. we rely on transport-level timeouts instead.
	}

	// ------------------------------------------------------------------
	// Build request
	// ------------------------------------------------------------------
	req, err := http.NewRequest("GET", opts.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot build HTTP request for %q: %w", opts.URL, err)
	}
	// GRUG: set User-Agent so servers don't block us as a bot.
	// some CDNs reject empty UA. "bindboss/1.0" is honest and sufficient.
	req.Header.Set("User-Agent", "bindboss/1.0")

	// ------------------------------------------------------------------
	// Execute request
	// ------------------------------------------------------------------
	fmt.Fprintf(os.Stderr, "[bindboss] downloading: %s\n", opts.URL)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf(
			"!!! FATAL: HTTP request failed for %q: %w\n"+
				"  Check your internet connection and that the URL is correct.", opts.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"!!! FATAL: server returned HTTP %d for %q\n"+
				"  Expected 200 OK. The download URL may be invalid or expired.",
			resp.StatusCode, opts.URL)
	}

	// ------------------------------------------------------------------
	// Determine destination path
	// ------------------------------------------------------------------
	destDir := opts.DestDir
	if destDir == "" {
		destDir = os.TempDir()
	}
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot create download directory %q: %w", destDir, err)
	}

	fileName := opts.FileName
	if fileName == "" {
		fileName = fileNameFromURL(opts.URL)
	}
	if fileName == "" {
		fileName = "bindboss-download"
	}

	destPath := filepath.Join(destDir, fileName)

	// ------------------------------------------------------------------
	// Stream response body to file with progress
	// GRUG: write to temp file first. rename on success. no partial files
	// left behind if download fails midway.
	// ------------------------------------------------------------------
	tmpFile, err := os.CreateTemp(destDir, ".bindboss-dl-*")
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot create temp file for download: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // GRUG: cleanup if rename never happens

	totalSize := resp.ContentLength // -1 if unknown

	var reader io.Reader = resp.Body
	if opts.OnProgress != nil && totalSize > 0 {
		reader = &progressReader{
			r:        resp.Body,
			total:    totalSize,
			callback: opts.OnProgress,
		}
	}

	written, err := io.Copy(tmpFile, reader)
	if err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf(
			"!!! FATAL: download interrupted after %d bytes for %q: %w\n"+
				"  The connection may have dropped. Try again.",
			written, opts.URL, err)
	}

	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot flush downloaded file: %w", err)
	}

	// GRUG: if server told us the size, verify we got all of it.
	// short download = corrupted file. FATAL. no running half an installer.
	if totalSize >= 0 && written != totalSize {
		return nil, fmt.Errorf(
			"!!! FATAL: download size mismatch for %q: expected %d bytes, got %d\n"+
				"  The download was truncated. Try again.",
			opts.URL, totalSize, written)
	}

	// ------------------------------------------------------------------
	// Rename temp to final path
	// ------------------------------------------------------------------
	if err := os.Rename(tmpPath, destPath); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot move downloaded file to %q: %w", destPath, err)
	}

	// GRUG: make it executable on Unix. installers need +x. harmless on data files.
	if runtime.GOOS != "windows" {
		os.Chmod(destPath, 0755) //nolint:errcheck
	}

	fmt.Fprintf(os.Stderr, "[bindboss] ✓ downloaded: %s (%d bytes)\n", destPath, written)

	// ------------------------------------------------------------------
	// Hash verification (optional)
	// GRUG: hash the file we actually wrote to disk. not the stream.
	// disk is ground truth — that's what the installer will run.
	// ------------------------------------------------------------------
	fileHash, err := hashFile(destPath)
	if err != nil {
		return nil, err
	}

	result := &Result{
		FilePath: destPath,
		Size:     written,
		SHA256:   fileHash,
	}

	if opts.ExpectedHash != "" {
		expected := strings.ToLower(strings.TrimSpace(opts.ExpectedHash))
		if fileHash != expected {
			return result, fmt.Errorf(
				"!!! FATAL: hash mismatch for downloaded file %q\n"+
					"  expected: %s\n"+
					"  got:      %s\n"+
					"  The file may be corrupted or tampered with. Do NOT run it.",
				destPath, expected, fileHash)
		}
		result.HashMatch = true
		fmt.Fprintf(os.Stderr, "[bindboss] ✓ hash verified: %s\n", fileHash)
	}

	return result, nil
}

// LaunchInstaller runs a downloaded installer file and returns immediately.
// The installer runs as a child process — we do NOT wait for it to exit
// because GUI installers spawn subprocesses and return quickly.
// Returns the exec.Cmd so caller can optionally wait on it.
//
// GRUG: platform-aware launch. .exe runs directly. .msi gets msiexec.
// .dmg gets "open". .sh gets "sh". no guessing. no silent "file not found".
func LaunchInstaller(filePath string) (*exec.Cmd, error) {
	if _, err := os.Stat(filePath); err != nil {
		return nil, fmt.Errorf("!!! FATAL: installer file not found at %q: %w", filePath, err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot resolve path for installer %q: %w", filePath, err)
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		switch ext {
		case ".msi":
			// GRUG: msiexec for .msi files. /i = install mode.
			cmd = exec.Command("msiexec", "/i", absPath)
		case ".exe":
			cmd = exec.Command(absPath)
		default:
			cmd = exec.Command(absPath)
		}

	case "darwin":
		switch ext {
		case ".dmg":
			// GRUG: "open" mounts the .dmg and shows it in Finder.
			cmd = exec.Command("open", absPath)
		case ".pkg":
			// GRUG: "open" also handles .pkg — launches Installer.app.
			cmd = exec.Command("open", absPath)
		default:
			cmd = exec.Command(absPath)
		}

	default: // linux and other unix
		switch ext {
		case ".sh", ".run":
			// GRUG: shell scripts need sh. might not have +x yet.
			cmd = exec.Command("sh", absPath)
		case ".appimage":
			cmd = exec.Command(absPath)
		case ".deb":
			// GRUG: try xdg-open for .deb — opens in software center if available.
			// fallback: tell user to run dpkg -i manually.
			if _, lookErr := exec.LookPath("xdg-open"); lookErr == nil {
				cmd = exec.Command("xdg-open", absPath)
			} else {
				return nil, fmt.Errorf(
					"!!! FATAL: cannot launch .deb installer automatically\n"+
						"  Run manually: sudo dpkg -i %s", absPath)
			}
		case ".rpm":
			if _, lookErr := exec.LookPath("xdg-open"); lookErr == nil {
				cmd = exec.Command("xdg-open", absPath)
			} else {
				return nil, fmt.Errorf(
					"!!! FATAL: cannot launch .rpm installer automatically\n"+
						"  Run manually: sudo rpm -i %s", absPath)
			}
		default:
			// GRUG: unknown extension on Linux. try running it directly.
			// if it's not executable, exec will fail with a clear error.
			cmd = exec.Command(absPath)
		}
	}

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Fprintf(os.Stderr, "[bindboss] launching installer: %s\n", absPath)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf(
			"!!! FATAL: cannot launch installer %q: %w\n"+
				"  Check that the file is a valid installer for your platform (%s/%s).",
			absPath, err, runtime.GOOS, runtime.GOARCH)
	}

	return cmd, nil
}

// DownloadAndInstall is the full flow: download → verify → launch → wait for user.
// This is the high-level function the installer GUI calls for each dep's stub.
//
// GRUG: this is the money function. does everything the old openBrowser did,
// but better. downloads the actual file instead of hoping user finds it.
func DownloadAndInstall(opts Options) (*Result, error) {
	// Step 1: Download
	result, err := Download(opts)
	if err != nil {
		return result, err
	}

	// Step 2: Launch installer
	cmd, err := LaunchInstaller(result.FilePath)
	if err != nil {
		return result, err
	}

	// Step 3: Wait for installer to finish (best effort)
	// GRUG: try to wait for the process. if it detaches (GUI installers do),
	// cmd.Wait() returns quickly and we proceed to user prompt.
	// either way, user confirms with Enter.
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// GRUG: give installer 2 seconds head start before prompting.
	// this way the installer window appears before we ask "press Enter".
	time.Sleep(2 * time.Second)

	select {
	case waitErr := <-done:
		if waitErr != nil {
			// GRUG: installer exited with error. warn but don't FATAL —
			// some installers return nonzero even on success (looking at you, msiexec).
			fmt.Fprintf(os.Stderr,
				"[bindboss] warning: installer process exited with: %v\n"+
					"[bindboss] this may or may not indicate a problem.\n", waitErr)
		} else {
			fmt.Fprintf(os.Stderr, "[bindboss] installer process completed.\n")
		}
	default:
		// GRUG: installer still running (GUI). that's fine. user will tell us when done.
		fmt.Fprintf(os.Stderr, "[bindboss] installer is running...\n")
	}

	return result, nil
}

// -----------------------------------------------------------------------------
// internal helpers
// -----------------------------------------------------------------------------

// fileNameFromURL extracts a filename from the last path segment of a URL.
// Returns empty string if URL has no usable path.
func fileNameFromURL(rawURL string) string {
	// GRUG: don't import net/url just for this. split on / and ? manually.
	// strip query string first
	base := rawURL
	if idx := strings.LastIndex(base, "?"); idx >= 0 {
		base = base[:idx]
	}
	// strip fragment
	if idx := strings.LastIndex(base, "#"); idx >= 0 {
		base = base[:idx]
	}
	// get last path segment
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	if base == "" {
		return ""
	}
	return base
}

// hashFile computes the hex-encoded SHA-256 of a file on disk.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("!!! FATAL: cannot open %q for hash verification: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("!!! FATAL: cannot read %q for hash verification: %w", path, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// progressReader wraps an io.Reader and calls a callback with download progress.
// Fires callback roughly every 64KB to avoid flooding on fast connections.
type progressReader struct {
	r          io.Reader
	total      int64
	downloaded int64
	callback   func(downloaded, total int64)
	lastReport int64
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	if n > 0 {
		p.downloaded += int64(n)
		// GRUG: report every 64KB or on final read. not every byte.
		if p.downloaded-p.lastReport >= 65536 || err == io.EOF {
			p.callback(p.downloaded, p.total)
			p.lastReport = p.downloaded
		}
	}
	return n, err
}