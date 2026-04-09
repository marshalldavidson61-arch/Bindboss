// archive_test.go
// =============================================================================
// GRUG: Tests for the archive cave. Verifies round-trip pack/extract,
// path sanitization, trailer magic, and payload location.
// =============================================================================

package archive_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/marshalldavidson61-arch/bindboss/internal/archive"
)

// makeTestDir creates a temporary directory with a known file tree:
//
//	root/
//	  hello.txt           "hello world"
//	  subdir/
//	    nested.txt        "nested content"
//	  script.sh           "#!/bin/sh\necho hi\n"  (executable)
func makeTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeFile(t, filepath.Join(dir, "hello.txt"), "hello world", 0644)
	if err := os.MkdirAll(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	writeFile(t, filepath.Join(dir, "subdir", "nested.txt"), "nested content", 0644)
	writeFile(t, filepath.Join(dir, "script.sh"), "#!/bin/sh\necho hi\n", 0755)

	return dir
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("writeFile %q: %v", path, err)
	}
}

// TestPackExtractRoundTrip verifies that Pack → Extract restores the exact
// file tree with correct contents.
func TestPackExtractRoundTrip(t *testing.T) {
	srcDir := makeTestDir(t)
	destDir := t.TempDir()

	var buf bytes.Buffer
	if err := archive.Pack(srcDir, &buf); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("Pack produced empty output")
	}

	if err := archive.Extract(&buf, destDir); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	cases := []struct {
		path    string
		content string
	}{
		{"hello.txt", "hello world"},
		{filepath.Join("subdir", "nested.txt"), "nested content"},
		{"script.sh", "#!/bin/sh\necho hi\n"},
	}

	for _, tc := range cases {
		got, err := os.ReadFile(filepath.Join(destDir, tc.path))
		if err != nil {
			t.Errorf("ReadFile %q after extract: %v", tc.path, err)
			continue
		}
		if string(got) != tc.content {
			t.Errorf("file %q: got %q, want %q", tc.path, got, tc.content)
		}
	}
}

// TestExtractPreservesExecutable verifies that executable permissions survive
// the pack/extract round trip.
func TestExtractPreservesExecutable(t *testing.T) {
	srcDir := makeTestDir(t)
	destDir := t.TempDir()

	var buf bytes.Buffer
	if err := archive.Pack(srcDir, &buf); err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if err := archive.Extract(&buf, destDir); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	fi, err := os.Stat(filepath.Join(destDir, "script.sh"))
	if err != nil {
		t.Fatalf("stat script.sh: %v", err)
	}
	if fi.Mode()&0111 == 0 {
		t.Errorf("script.sh lost executable bit: mode=%v", fi.Mode())
	}
}

// makeMaliciousTarGz builds a tar.gz containing an entry with a "../" path
// traversal. Used to verify Extract rejects it.
func makeMaliciousTarGz(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	content := []byte("evil content")
	hdr := &tar.Header{
		Name:     "../evil.txt",
		Mode:     0644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write evil tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("write evil tar content: %v", err)
	}
	tw.Close()
	gz.Close()
	return &buf
}

// TestExtractPathTraversalBlocked verifies that archives with "../" paths
// are rejected to prevent directory traversal attacks.
func TestExtractPathTraversalBlocked(t *testing.T) {
	malicious := makeMaliciousTarGz(t)
	destDir := t.TempDir()

	err := archive.Extract(malicious, destDir)
	if err == nil {
		t.Fatal("Extract should have rejected path traversal entry but succeeded")
	}
	t.Logf("correctly rejected path traversal: %v", err)
}

// TestAppendPayloadAndFind verifies the full self-extracting binary pattern:
// write a fake stub binary, append a payload, then find and extract it.
func TestAppendPayloadAndFind(t *testing.T) {
	srcDir := makeTestDir(t)

	// GRUG: Fake stub binary — not a real ELF, just some bytes.
	tmpBin := filepath.Join(t.TempDir(), "fakestub")
	stubContent := []byte("FAKESTUB_BINARY_CONTENT_1234567890")
	if err := os.WriteFile(tmpBin, stubContent, 0755); err != nil {
		t.Fatalf("write fake stub: %v", err)
	}

	// Append payload to the fake stub.
	if err := archive.AppendPayload(tmpBin, srcDir); err != nil {
		t.Fatalf("AppendPayload: %v", err)
	}

	// Verify binary grew beyond the original stub size.
	fi, err := os.Stat(tmpBin)
	if err != nil {
		t.Fatalf("stat packed binary: %v", err)
	}
	if fi.Size() <= int64(len(stubContent)) {
		t.Errorf("packed binary should be larger than stub: got %d bytes", fi.Size())
	}

	// Find the payload by seeking to the trailer.
	reader, err := archive.FindPayload(tmpBin)
	if err != nil {
		t.Fatalf("FindPayload: %v", err)
	}
	defer reader.Close()

	// Extract from the found payload and spot-check a file.
	destDir := t.TempDir()
	if err := archive.Extract(reader, destDir); err != nil {
		t.Fatalf("Extract from payload: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(destDir, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile hello.txt after payload extract: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("hello.txt: got %q, want %q", got, "hello world")
	}
}

// TestFindPayloadOnUnpackedBinary verifies that FindPayload returns a clear
// FATAL error when the binary has no bindboss payload (no magic trailer).
func TestFindPayloadOnUnpackedBinary(t *testing.T) {
	tmpBin := filepath.Join(t.TempDir(), "notpacked")
	// Write 1024 zero bytes — no magic trailer.
	if err := os.WriteFile(tmpBin, make([]byte, 1024), 0755); err != nil {
		t.Fatalf("write unpacked binary: %v", err)
	}

	_, err := archive.FindPayload(tmpBin)
	if err == nil {
		t.Fatal("FindPayload should fail on unpacked binary but succeeded")
	}
	t.Logf("correctly rejected unpacked binary: %v", err)
}

// TestPackEmptyDirError verifies that packing a non-existent directory fails
// with a FATAL error, not a silent empty archive.
func TestPackNonExistentDirError(t *testing.T) {
	var buf bytes.Buffer
	err := archive.Pack("/this/does/not/exist/at/all", &buf)
	if err == nil {
		t.Fatal("Pack should fail on non-existent directory but succeeded")
	}
	t.Logf("correctly rejected non-existent dir: %v", err)
}