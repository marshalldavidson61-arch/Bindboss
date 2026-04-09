// download_test.go
// =============================================================================
// GRUG: Tests for the download cave. Spin up a real HTTP server, download
// a file, verify hash, check error paths. No mocks — real sockets, real files.
//
// ---
// ACADEMIC: Tests use net/http/httptest.Server which binds to localhost on a
// random port. This provides end-to-end coverage of the HTTP client including
// transport, redirects, and header parsing — mock-based tests would miss
// transport-layer bugs.
// =============================================================================

package download

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testPayload is a small known payload for testing.
const testPayload = "Hello from bindboss download test!"

func testPayloadHash() string {
	h := sha256.Sum256([]byte(testPayload))
	return hex.EncodeToString(h[:])
}

func TestDownload_Success(t *testing.T) {
	// GRUG: spin up server, serve testPayload, download it, check bytes match.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testPayload)))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testPayload))
	}))
	defer srv.Close()

	destDir := t.TempDir()

	result, err := Download(Options{
		URL:     srv.URL + "/installer.exe",
		DestDir: destDir,
	})
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}

	if result.Size != int64(len(testPayload)) {
		t.Errorf("size: got %d, want %d", result.Size, len(testPayload))
	}

	// GRUG: verify file on disk has correct content
	data, err := os.ReadFile(result.FilePath)
	if err != nil {
		t.Fatalf("cannot read downloaded file: %v", err)
	}
	if string(data) != testPayload {
		t.Errorf("content mismatch: got %q, want %q", string(data), testPayload)
	}

	// GRUG: check filename was derived from URL
	if filepath.Base(result.FilePath) != "installer.exe" {
		t.Errorf("filename: got %q, want %q", filepath.Base(result.FilePath), "installer.exe")
	}
}

func TestDownload_HashVerification(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testPayload))
	}))
	defer srv.Close()

	destDir := t.TempDir()
	expectedHash := testPayloadHash()

	// Good hash — should succeed
	result, err := Download(Options{
		URL:          srv.URL + "/file.bin",
		DestDir:      destDir,
		ExpectedHash: expectedHash,
	})
	if err != nil {
		t.Fatalf("Download with correct hash failed: %v", err)
	}
	if !result.HashMatch {
		t.Error("HashMatch should be true when hash matches")
	}
	if result.SHA256 != expectedHash {
		t.Errorf("SHA256: got %q, want %q", result.SHA256, expectedHash)
	}

	// Bad hash — should FATAL
	destDir2 := t.TempDir()
	_, err = Download(Options{
		URL:          srv.URL + "/file.bin",
		DestDir:      destDir2,
		ExpectedHash: "0000000000000000000000000000000000000000000000000000000000000000",
	})
	if err == nil {
		t.Fatal("Download with wrong hash should have returned error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("error should mention hash mismatch, got: %v", err)
	}
}

func TestDownload_HTTPError(t *testing.T) {
	// GRUG: server returns 404. download must FATAL. no silent empty file.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := Download(Options{
		URL:     srv.URL + "/missing.exe",
		DestDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("Download of 404 should have returned error")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error should mention HTTP 404, got: %v", err)
	}
}

func TestDownload_EmptyURL(t *testing.T) {
	_, err := Download(Options{URL: ""})
	if err == nil {
		t.Fatal("Download with empty URL should have returned error")
	}
	if !strings.Contains(err.Error(), "URL is empty") {
		t.Errorf("error should mention empty URL, got: %v", err)
	}
}

func TestDownload_Progress(t *testing.T) {
	// GRUG: make a payload big enough to trigger progress reporting (>64KB)
	bigPayload := strings.Repeat("X", 200000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(bigPayload)))
		w.Write([]byte(bigPayload))
	}))
	defer srv.Close()

	var progressCalls int
	_, err := Download(Options{
		URL:     srv.URL + "/big.bin",
		DestDir: t.TempDir(),
		OnProgress: func(downloaded, total int64) {
			progressCalls++
			if total != int64(len(bigPayload)) {
				t.Errorf("progress total: got %d, want %d", total, len(bigPayload))
			}
		},
	})
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if progressCalls == 0 {
		t.Error("progress callback was never called for 200KB download")
	}
}

func TestDownload_CustomFileName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("data"))
	}))
	defer srv.Close()

	destDir := t.TempDir()
	result, err := Download(Options{
		URL:      srv.URL + "/anything",
		DestDir:  destDir,
		FileName: "my-custom-name.exe",
	})
	if err != nil {
		t.Fatalf("Download failed: %v", err)
	}
	if filepath.Base(result.FilePath) != "my-custom-name.exe" {
		t.Errorf("filename: got %q, want %q", filepath.Base(result.FilePath), "my-custom-name.exe")
	}
}

func TestFileNameFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/julia-1.9.3-linux-x86_64.tar.gz", "julia-1.9.3-linux-x86_64.tar.gz"},
		{"https://cdn.example.com/releases/v2/installer.exe?token=abc&sig=def", "installer.exe"},
		{"https://example.com/file.dmg#anchor", "file.dmg"},
		{"https://example.com/", ""},
		{"https://example.com", "example.com"},
	}
	for _, tt := range tests {
		got := fileNameFromURL(tt.url)
		if got != tt.want {
			t.Errorf("fileNameFromURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}