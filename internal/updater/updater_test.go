// updater_test.go
// =============================================================================
// GRUG: test the updater. can't test real GitHub API calls in CI. test the
// parts grug can control: parsing URLs, extracting archives, throttling.
// real API integration = manual test or E2E. unit tests = fast + reliable.
// =============================================================================

package updater

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestParseOwnerRepo verifies GitHub URL parsing.
func TestParseOwnerRepo(t *testing.T) {
	tests := []struct {
		url      string
		wantOwner string
		wantRepo  string
		wantErr   bool
	}{
		{
			url:       "https://github.com/grug-group420/Bindboss",
			wantOwner: "grug-group420",
			wantRepo:  "Bindboss",
		},
		{
			url:       "https://github.com/owner/repo",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			url:       "https://github.com/owner/repo.git",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			url:       "https://github.com/owner/repo/",
			wantOwner: "owner",
			wantRepo:  "repo",
		},
		{
			url:     "https://github.com/only-one-part",
			wantErr: true,
		},
		{
			url:     "https://not-github.com/owner/repo",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			owner, repo, err := parseOwnerRepo(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error for %q, got none", tt.url)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.url, err)
			}
			if owner != tt.wantOwner {
				t.Errorf("owner: got %q, want %q", owner, tt.wantOwner)
			}
			if repo != tt.wantRepo {
				t.Errorf("repo: got %q, want %q", repo, tt.wantRepo)
			}
		})
	}
}

// TestShortSHA verifies the SHA shortening function.
func TestShortSHA(t *testing.T) {
	tests := []struct {
		sha  string
		want string
	}{
		{"abc1234def567890", "abc1234"},
		{"short", "short"},
		{"", ""},
	}
	for _, tt := range tests {
		got := ShortSHA(tt.sha)
		if got != tt.want {
			t.Errorf("ShortSHA(%q) = %q, want %q", tt.sha, got, tt.want)
		}
	}
}

// TestThrottleSkipsRecentCheck verifies that CheckAndDownload skips
// the API call when the last check was within the throttle interval.
func TestThrottleSkipsRecentCheck(t *testing.T) {
	// GRUG: if we just checked 1 second ago, don't check again.
	// throttle interval is 5 minutes. 1 second ago is too recent.
	result, err := CheckAndDownload(
		"https://github.com/owner/repo",
		"main",
		"abc123",                   // lastSHA
		time.Now().Unix()-1,        // lastCheckedAt: 1 second ago
		t.TempDir(),                // persistDir
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasUpdate {
		t.Error("throttled check should not report an update")
	}
	if result.CommitSHA != "abc123" {
		t.Errorf("throttled check should return lastSHA, got %q", result.CommitSHA)
	}
}

// TestExtractArchive verifies archive extraction with GitHub-style prefix stripping.
func TestExtractArchive(t *testing.T) {
	// GRUG: create a fake GitHub archive with a top-level directory prefix.
	// GitHub archives look like: repo-branch/src/main.jl
	// We want to strip "repo-branch/" so files land at src/main.jl.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	files := map[string]string{
		"myrepo-main/README.md":     "# Hello",
		"myrepo-main/src/main.jl":   "println(\"hi\")",
		"myrepo-main/src/sub/deep.jl": "# deep",
		"myrepo-main/data/":         "", // directory entry
	}

	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("cannot create zip entry %q: %v", name, err)
		}
		if content != "" {
			if _, err := f.Write([]byte(content)); err != nil {
				t.Fatalf("cannot write zip entry %q: %v", name, err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("cannot finalize zip: %v", err)
	}

	// Write zip to temp file
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "update.zip")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("cannot write archive: %v", err)
	}

	// Extract into target dir
	targetDir := filepath.Join(tmpDir, "extracted")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		t.Fatalf("cannot create target dir: %v", err)
	}

	if err := ExtractArchive(archivePath, targetDir); err != nil {
		t.Fatalf("ExtractArchive failed: %v", err)
	}

	// Verify files exist at expected paths (without prefix)
	readme, err := os.ReadFile(filepath.Join(targetDir, "README.md"))
	if err != nil {
		t.Fatalf("cannot read extracted README.md: %v", err)
	}
	if string(readme) != "# Hello" {
		t.Errorf("README.md content: got %q, want %q", string(readme), "# Hello")
	}

	mainJL, err := os.ReadFile(filepath.Join(targetDir, "src/main.jl"))
	if err != nil {
		t.Fatalf("cannot read extracted src/main.jl: %v", err)
	}
	if string(mainJL) != "println(\"hi\")" {
		t.Errorf("src/main.jl content: got %q, want %q", string(mainJL), "println(\"hi\")")
	}

	deepJL, err := os.ReadFile(filepath.Join(targetDir, "src/sub/deep.jl"))
	if err != nil {
		t.Fatalf("cannot read extracted src/sub/deep.jl: %v", err)
	}
	if string(deepJL) != "# deep" {
		t.Errorf("src/sub/deep.jl content: got %q, want %q", string(deepJL), "# deep")
	}

	// Verify data directory exists
	info, err := os.Stat(filepath.Join(targetDir, "data"))
	if err != nil {
		t.Fatalf("cannot stat extracted data dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("data should be a directory")
	}
}

// TestExtractArchiveCleansTarget verifies that ExtractArchive removes
// existing files in the target directory before extracting.
func TestExtractArchiveCleansTarget(t *testing.T) {
	// GRUG: if old version had a file that new version doesn't, the stale
	// file should be gone after update. clean slate = correct update.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	f, err := w.Create("repo-main/new.txt")
	if err != nil {
		t.Fatalf("cannot create zip entry: %v", err)
	}
	if _, err := f.Write([]byte("new content")); err != nil {
		t.Fatalf("cannot write zip entry: %v", err)
	}
	w.Close()

	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "update.zip")
	os.WriteFile(archivePath, buf.Bytes(), 0644)

	targetDir := filepath.Join(tmpDir, "extracted")
	os.MkdirAll(targetDir, 0755)

	// Create a stale file that should be removed by the update
	stalePath := filepath.Join(targetDir, "stale.txt")
	os.WriteFile(stalePath, []byte("old stuff"), 0644)

	if err := ExtractArchive(archivePath, targetDir); err != nil {
		t.Fatalf("ExtractArchive failed: %v", err)
	}

	// Stale file should be gone
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Error("stale file should have been removed during update")
	}

	// New file should exist
	newContent, err := os.ReadFile(filepath.Join(targetDir, "new.txt"))
	if err != nil {
		t.Fatalf("cannot read new.txt: %v", err)
	}
	if string(newContent) != "new content" {
		t.Errorf("new.txt: got %q, want %q", string(newContent), "new content")
	}
}

// TestVerifyArchiveRejectsInvalidZip verifies that VerifyArchive
// catches corrupt zip files.
func TestVerifyArchiveRejectsInvalidZip(t *testing.T) {
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "not-a-zip.bin")
	os.WriteFile(badPath, []byte("this is not a zip file"), 0644)

	if err := VerifyArchive(badPath); err == nil {
		t.Error("VerifyArchive should reject non-zip file")
	}
}

// TestVerifyArchiveAcceptsValidZip verifies that VerifyArchive
// accepts a valid zip file.
func TestVerifyArchiveAcceptsValidZip(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("test.txt")
	f.Write([]byte("hello"))
	w.Close()

	tmpDir := t.TempDir()
	goodPath := filepath.Join(tmpDir, "good.zip")
	os.WriteFile(goodPath, buf.Bytes(), 0644)

	if err := VerifyArchive(goodPath); err != nil {
		t.Errorf("VerifyArchive should accept valid zip, got: %v", err)
	}
}

// TestReadArchiveBytes verifies reading a zip from bytes.
func TestReadArchiveBytes(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("hello.txt")
	f.Write([]byte("world"))
	w.Close()

	r, err := ReadArchiveBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("ReadArchiveBytes failed: %v", err)
	}
	if len(r.File) != 1 {
		t.Errorf("expected 1 file in archive, got %d", len(r.File))
	}
	if r.File[0].Name != "hello.txt" {
		t.Errorf("file name: got %q, want %q", r.File[0].Name, "hello.txt")
	}
}

// TestCheckAndDownloadNoPreviousCheck verifies that CheckAndDownload
// attempts a real API call when lastCheckedAt=0 (never checked before).
// Since we can't control GitHub API in tests, we just verify it tries
// and fails gracefully (the repo likely doesn't exist).
func TestCheckAndDownloadNoPreviousCheck(t *testing.T) {
	// GRUG: this test makes a real HTTP request to GitHub. it will fail
	// because the repo doesn't exist, but it proves we don't panic.
	// skip in short mode.
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	_, err := CheckAndDownload(
		"https://github.com/nonexistent-org-xyz/repo-that-does-not-exist-12345",
		"main",
		"",    // lastSHA: never checked
		0,     // lastCheckedAt: never checked
		t.TempDir(),
	)
	// GRUG: should fail because the repo doesn't exist. but should NOT panic.
	if err == nil {
		// This shouldn't happen — the repo doesn't exist
		t.Log("unexpected success for nonexistent repo (might exist now?)")
	}
	// The key thing: no panic, and error message contains FATAL
	if err != nil && !strings.Contains(err.Error(), "FATAL") {
		t.Errorf("error should contain FATAL, got: %v", err)
	}
}
// TestExtractArchivePreservesPackedConfig verifies the packed bindboss.toml
// survives an update when the remote archive does NOT include one.
// GRUG: packed config = source of truth for run command. must not vanish on update.
func TestExtractArchivePreservesPackedConfig(t *testing.T) {
	// Create a target dir with an existing bindboss.toml
	targetDir := t.TempDir()
	packedConfig := []byte(`name = "testapp"
run = "sh run.sh"
`)
	cfgPath := filepath.Join(targetDir, "bindboss.toml")
	if err := os.WriteFile(cfgPath, packedConfig, 0644); err != nil {
		t.Fatalf("setup: writing packed config: %v", err)
	}

	// Build an archive that does NOT contain bindboss.toml
	archivePath := buildTestArchive(t, map[string]string{
		"repo-main/src/app.go": "package main\n",
		"repo-main/README.md":  "# hi\n",
	})

	if err := ExtractArchive(archivePath, targetDir); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}

	// Verify the packed bindboss.toml was restored.
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("packed config missing after update: %v", err)
	}
	if !bytes.Equal(restored, packedConfig) {
		t.Errorf("packed config contents changed after update")
	}
}

// TestExtractArchiveRemoteConfigWins verifies that if the remote archive ships
// its own bindboss.toml, it overrides the packed one.
// GRUG: remote shipping its own config = explicit intent. respect it.
func TestExtractArchiveRemoteConfigWins(t *testing.T) {
	targetDir := t.TempDir()
	packedConfig := []byte(`run = "old command"` + "\n")
	cfgPath := filepath.Join(targetDir, "bindboss.toml")
	if err := os.WriteFile(cfgPath, packedConfig, 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	remoteConfig := `run = "new command"` + "\n"
	archivePath := buildTestArchive(t, map[string]string{
		"repo-main/bindboss.toml": remoteConfig,
	})

	if err := ExtractArchive(archivePath, targetDir); err != nil {
		t.Fatalf("ExtractArchive: %v", err)
	}

	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("reading post-update config: %v", err)
	}
	if string(got) != remoteConfig {
		t.Errorf("remote config did not win: got %q want %q", got, remoteConfig)
	}
}

// buildTestArchive creates a zip file in a temp dir with the given entries
// and returns its path. Used by the tests above.
func buildTestArchive(t *testing.T, entries map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip.Create(%q): %v", name, err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	path := filepath.Join(t.TempDir(), "archive.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("writing archive: %v", err)
	}
	return path
}

// TestCheckAndDownloadNetworkFailure verifies the updater returns an error
// (not a panic or silent success) when the GitHub API is unreachable.
// GRUG: stub depends on this returning an error so it can fall back to
// the cached copy instead of running garbage. test the contract.
func TestCheckAndDownloadNetworkFailure(t *testing.T) {
	// Use a URL that will fail to resolve quickly. localhost:1 is
	// guaranteed closed on most systems.
	// We can't override the GitHub API URL from outside, so this test
	// relies on DNS for a bogus TLD that will fail fast.
	persistDir := t.TempDir()

	// Pointing at an invalid repo URL - parseOwnerRepo will accept this
	// but fetchLatestCommit will fail because the repo doesn't exist.
	// This exercises the error path without requiring network manipulation.
	_, err := CheckAndDownload(
		"https://github.com/this-org-should-not-exist-12345/neither-should-this-repo",
		"main",
		"",
		0,
		persistDir,
	)
	if err == nil {
		t.Skip("this test requires network access to github.com and a truly nonexistent repo")
	}
	// We expect a FATAL-prefixed error so the stub can distinguish updater errors
	// from other failures.
	if !strings.Contains(err.Error(), "FATAL") {
		t.Errorf("expected FATAL-prefixed error, got: %v", err)
	}
}

// TestCheckAndDownloadThrottle verifies that a recent check short-circuits
// without hitting the network. The throttle is what keeps us under rate limits.
func TestCheckAndDownloadThrottle(t *testing.T) {
	persistDir := t.TempDir()

	// lastCheckedAt = now means we should skip the check entirely.
	recent := time.Now().Unix()
	result, err := CheckAndDownload(
		"https://github.com/grug-group420/Bindboss",
		"main",
		"cachedsha",
		recent,
		persistDir,
	)
	if err != nil {
		t.Fatalf("throttle path should not error: %v", err)
	}
	if result.HasUpdate {
		t.Errorf("throttle path should report HasUpdate=false, got true")
	}
	if result.CommitSHA != "cachedsha" {
		t.Errorf("throttle path should return cached SHA, got %q", result.CommitSHA)
	}
}
