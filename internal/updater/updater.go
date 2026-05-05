// updater.go
// =============================================================================
// GRUG: grug want to know if remote repo has new stuff. grug ask GitHub API
// "hey, latest commit on this branch?" GitHub says SHA. grug compare to SHA
// grug saved last time. same SHA = nothing new, carry on. different SHA = new
// stuff! grug download zip and replace files in persist dir. simple.
//
// GRUG: only GitHub for now. one host, done right, then extend later.
// URL must be https://github.com/owner/repo. grug validate this in config.
//
// GRUG: GitHub API has rate limits. 60 requests/hour for unauthenticated.
// grug check at most once per 5 minutes. if checked recently, skip.
// no point burning API calls on every binary run. throttle = good.
//
// GRUG: download the zip from GitHub's archive endpoint. extract into the
// persist directory. if anything goes wrong, FATAL. no silent failures.
// partial update = broken install. better to crash loudly than run broken.
//
// -----------------------------------------------------------------------------
// ACADEMIC FOOTER:
// The updater queries the GitHub REST API (v3) for the latest commit on a
// given branch, compares it to the previously-seen SHA in the state file,
// and if different, downloads and extracts the latest archive. All HTTP
// errors are fatal — a partial or failed update leaves the persist directory
// in an inconsistent state, so we prefer clean failures over silent
// degradation.
//
// Rate limiting: unauthenticated GitHub API allows 60 requests/hour. The
// throttle interval (default 5 minutes) prevents excessive calls. The
// update_checked_at timestamp in the state file gates each check.
//
// Archive format: GitHub provides zipball archives at
//   https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip
// The archive contains a single top-level directory
// ({repo}-{branch|sha}/). The updater strips this prefix during extraction
// so files land at the expected paths within the persist directory.
// =============================================================================

package updater

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ThrottleInterval controls how often we hit the GitHub API.
// GRUG: don't want to spam GitHub. 5 minutes between checks is plenty.
// if binary runs 100 times a day, that's still only ~288 API calls/day
// per binary. well within the 60/hour unauthenticated limit... wait.
// 60/hour = 1/minute. 5-minute throttle = 12/hour. fine.
const ThrottleInterval = 5 * time.Minute

// httpTimeout is the timeout for all HTTP requests.
// GRUG: don't hang forever if GitHub is slow. 30 seconds is generous.
const httpTimeout = 30 * time.Second

// GitHubCommit represents the relevant fields from the GitHub API response
// for GET /repos/{owner}/{repo}/commits/{ref}.
type GitHubCommit struct {
	SHA string `json:"sha"`
}

// Result holds the outcome of an update check.
type Result struct {
	// HasUpdate is true if the remote has a new commit (SHA differs from saved).
	HasUpdate bool
	// CommitSHA is the latest commit SHA from the remote.
	CommitSHA string
	// ArchivePath is the path to the downloaded zip, if HasUpdate is true.
	// Caller is responsible for cleaning this up after extraction.
	ArchivePath string
}

// parseOwnerRepo extracts "owner" and "repo" from a validated GitHub URL.
// Input must be "https://github.com/owner/repo" (already validated by config).
// GRUG: simple string split. config already validated the format. trust it.
func parseOwnerRepo(url string) (owner, repo string, err error) {
	trimmed := strings.TrimSuffix(url, "/")
	trimmed = strings.TrimSuffix(trimmed, ".git")
	path := strings.TrimPrefix(trimmed, "https://github.com/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf(
			"!!! FATAL: cannot parse owner/repo from URL %q", url)
	}
	return parts[0], parts[1], nil
}

// CheckAndDownload checks the remote repo for new commits and downloads
// the latest archive if there's an update.
//
// Parameters:
//   - repoURL: validated GitHub repo URL (https://github.com/owner/repo)
//   - branch: branch to track (empty = "main")
//   - lastSHA: the commit SHA saved in state (empty = first check)
//   - lastCheckedAt: unix timestamp of last check (0 = never checked)
//   - persistDir: the directory where extracted files live
//
// Returns a Result indicating whether an update was found and where the
// downloaded archive lives. The caller must extract it and clean up.
//
// GRUG: this is the main function. check GitHub. if new, download zip.
// return result so stub can decide what to do. updater doesn't extract
// because stub already has extraction logic. separation of concerns.
func CheckAndDownload(repoURL, branch, lastSHA string, lastCheckedAt int64, persistDir string) (Result, error) {
	// GRUG: throttle. if we checked recently, don't hit GitHub again.
	// save API calls. save time. nobody needs per-second update checks.
	if lastCheckedAt > 0 {
		elapsed := time.Since(time.Unix(lastCheckedAt, 0))
		if elapsed < ThrottleInterval {
			return Result{HasUpdate: false, CommitSHA: lastSHA}, nil
		}
	}

	if branch == "" {
		branch = "main"
	}

	owner, repo, err := parseOwnerRepo(repoURL)
	if err != nil {
		return Result{}, err
	}

	// GRUG: ask GitHub for latest commit on the branch.
	commitSHA, err := fetchLatestCommit(owner, repo, branch)
	if err != nil {
		return Result{}, fmt.Errorf(
			"!!! FATAL: cannot check remote update for %s/%s branch %q: %w",
			owner, repo, branch, err)
	}

	// GRUG: same SHA = nothing new. save the check timestamp and move on.
	if commitSHA == lastSHA {
		return Result{HasUpdate: false, CommitSHA: commitSHA}, nil
	}

	// GRUG: new commit! download the zip archive.
	fmt.Printf("[bindboss] update detected: remote has new commit %s (was %s)\n",
		ShortSHA(commitSHA), ShortSHA(lastSHA))

	archivePath, err := downloadArchive(owner, repo, branch, persistDir)
	if err != nil {
		return Result{}, fmt.Errorf(
			"!!! FATAL: cannot download update archive for %s/%s: %w",
			owner, repo, err)
	}

	return Result{
		HasUpdate:   true,
		CommitSHA:   commitSHA,
		ArchivePath: archivePath,
	}, nil
}

// fetchLatestCommit queries the GitHub API for the latest commit SHA on a branch.
// GRUG: simple GET to GitHub API. no auth = 60 req/hour. fine for our throttle.
func fetchLatestCommit(owner, repo, branch string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits/%s",
		owner, repo, branch)

	client := &http.Client{Timeout: httpTimeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("cannot create GitHub API request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	// GRUG: tell GitHub who's asking. polite and helps with rate limits.
	req.Header.Set("User-Agent", "bindboss-updater")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode,
			string(body))
	}

	var commit GitHubCommit
	if err := json.NewDecoder(resp.Body).Decode(&commit); err != nil {
		return "", fmt.Errorf("cannot decode GitHub API response: %w", err)
	}

	if commit.SHA == "" {
		return "", fmt.Errorf("!!! FATAL: GitHub API returned empty commit SHA for %s/%s@%s",
			owner, repo, branch)
	}

	return commit.SHA, nil
}

// downloadArchive downloads the zip archive for the given branch from GitHub.
// The archive is saved to a temp file in the persist directory.
// GRUG: GitHub gives us a zip. save it next to persist dir. stub extracts
// it into persist dir after download. caller cleans up temp file.
func downloadArchive(owner, repo, branch, persistDir string) (string, error) {
	url := fmt.Sprintf("https://github.com/%s/%s/archive/refs/heads/%s.zip",
		owner, repo, branch)

	fmt.Printf("[bindboss] downloading update from %s\n", url)

	client := &http.Client{Timeout: 5 * time.Minute} // GRUG: big repos need time.
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("cannot create download request: %w", err)
	}
	req.Header.Set("User-Agent", "bindboss-updater")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with HTTP %d", resp.StatusCode)
	}

	// GRUG: save to a temp file in the OS tmp dir, NOT the persist dir.
	// if we saved inside persist, ExtractArchive would wipe our own zip before
	// reading it. separate location = safe. os.CreateTemp handles uniqueness.
	_ = persistDir // silence unused-param lint; kept in signature for future use
	tmpFile, err := os.CreateTemp("", "bindboss-update-*.zip")
	if err != nil {
		return "", fmt.Errorf("!!! FATAL: cannot create temp file for update download: %w", err)
	}
	tmpPath := tmpFile.Name()

	// GRUG: copy with limit. don't want to fill disk with a rogue response.
	// 500MB is a generous upper bound for a source repo archive.
	written, err := io.Copy(tmpFile, io.LimitReader(resp.Body, 500*1024*1024))
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("!!! FATAL: cannot write update archive: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("!!! FATAL: cannot flush update archive: %w", err)
	}

	fmt.Printf("[bindboss] downloaded update archive (%d bytes)\n", written)
	return tmpPath, nil
}

// ExtractArchive extracts a GitHub zip archive into the target directory.
// GitHub archives contain a single top-level directory like "repo-branch/"
// or "repo-sha/". This function strips that prefix so files land at the
// expected paths within the target directory.
//
// GRUG: GitHub zip has annoying top-level dir. strip it. files should land
// where they belong, not nested under "repo-main-abc1234/". simple.
func ExtractArchive(archivePath, targetDir string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot open update archive %q: %w", archivePath, err)
	}
	defer r.Close()

	// GRUG: find the top-level directory prefix from the first entry.
	// GitHub archives always have "{repo}-{branch}/" as the first path component.
	var prefix string
	for _, f := range r.File {
		parts := strings.SplitN(f.Name, "/", 2)
		if len(parts) > 0 {
			prefix = parts[0] + "/"
			break
		}
	}
	if prefix == "" {
		return fmt.Errorf("!!! FATAL: update archive is empty or has no top-level directory")
	}

	// GRUG: preserve the packed bindboss.toml across updates. this file
	// defines WHAT the binary does (run command, hooks, etc). if the remote
	// repo doesn't ship its own bindboss.toml, we must keep ours or the
	// binary becomes unusable after an update. if the remote DOES ship one,
	// the extraction loop will overwrite ours — remote wins (power-user mode).
	packedConfigPath := filepath.Join(targetDir, "bindboss.toml")
	var savedConfig []byte
	if data, rerr := os.ReadFile(packedConfigPath); rerr == nil {
		savedConfig = data
	}

	// GRUG: clear target dir before extracting. fresh update = clean slate.
	// if we just overlay, deleted files from old version would linger.
	if err := os.RemoveAll(targetDir); err != nil {
		return fmt.Errorf("!!! FATAL: cannot clear target directory %q for update: %w", targetDir, err)
	}
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("!!! FATAL: cannot recreate target directory %q: %w", targetDir, err)
	}

	for _, f := range r.File {
		// GRUG: strip the top-level dir prefix. "repo-branch/src/main.jl" → "src/main.jl"
		if !strings.HasPrefix(f.Name, prefix) {
			return fmt.Errorf("!!! FATAL: archive entry %q does not have expected prefix %q", f.Name, prefix)
		}
		relPath := strings.TrimPrefix(f.Name, prefix)
		if relPath == "" {
			continue // GRUG: skip the top-level directory entry itself.
		}

		targetPath := filepath.Join(targetDir, relPath)

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, f.Mode()); err != nil {
				return fmt.Errorf("!!! FATAL: cannot create directory %q: %w", targetPath, err)
			}
			continue
		}

		// GRUG: ensure parent directory exists before writing file.
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("!!! FATAL: cannot create parent directory for %q: %w", targetPath, err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot open archive entry %q: %w", f.Name, err)
		}

		outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
		if err != nil {
			rc.Close()
			return fmt.Errorf("!!! FATAL: cannot create file %q: %w", targetPath, err)
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			outFile.Close()
			rc.Close()
			return fmt.Errorf("!!! FATAL: cannot write file %q: %w", targetPath, err)
		}
		outFile.Close()
		rc.Close()
	}

	// GRUG: if the remote archive did NOT include a bindboss.toml of its own,
	// restore the packed one so the binary still knows its run command.
	// if the remote DID include one, it was already written in the loop above
	// and we respect it — user wanted remote to own the config.
	if savedConfig != nil {
		if _, statErr := os.Stat(packedConfigPath); os.IsNotExist(statErr) {
			if werr := os.WriteFile(packedConfigPath, savedConfig, 0644); werr != nil {
				return fmt.Errorf(
					"!!! FATAL: cannot restore packed bindboss.toml after update: %w", werr)
			}
		}
	}

	return nil
}

// shortSHA returns the first 7 characters of a commit SHA for display.
// GRUG: full SHA is ugly in logs. 7 chars is standard short SHA. nice.
func ShortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// VerifyArchive checks that an archive file is a valid zip.
// GRUG: before extracting, make sure the downloaded file isn't garbage.
// corrupt archive = corrupt install. catch it early.
func VerifyArchive(archivePath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: update archive %q is not a valid zip: %w", archivePath, err)
	}
	r.Close()
	return nil
}

// ReadArchiveBytes reads an archive from raw bytes and returns a *zip.Reader.
// Useful for testing without writing to disk.
func ReadArchiveBytes(data []byte) (*zip.Reader, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot read zip from bytes: %w", err)
	}
	return r, nil
}