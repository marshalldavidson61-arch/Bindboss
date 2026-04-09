// archive.go
// =============================================================================
// GRUG: This is the archive cave. Packs a directory into a gzip-compressed tar
// stream. The stream gets appended to the stub binary, making it self-extracting.
// On the other end, Extract() reads that stream back out and restores the tree.
//
// ACADEMIC: The self-extracting binary pattern works by appending a payload
// to a valid ELF/Mach-O/PE binary. The OS executes the binary normally (the
// loader only reads the ELF headers, which are at the front). The binary then
// seeks to a known offset near its own EOF to find the payload boundary marker,
// reads the tar stream from that point, and extracts it. The boundary marker
// is a fixed 16-byte magic sequence followed by an 8-byte big-endian offset
// recording where the tar data begins. This gives O(1) payload location with
// no scanning.
//
// Payload layout (appended after the stub ELF):
//   [tar.gz data ...] [8-byte big-endian: offset of tar.gz start] [16-byte magic]
//
// The magic is at the very end so the stub can seek(-24, EOF) to find it.
// =============================================================================

package archive

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Magic is the 16-byte boundary marker written at the end of a packed binary.
// Chosen to be unlikely to appear in normal binary data.
var Magic = [16]byte{
	0xBB, 0x05, 0x5B, 0x0B, 0x1C, 0xEB, 0x05, 0x5B,
	0x0D, 0xEA, 0xDB, 0x0B, 0xBB, 0x0B, 0x05, 0x5B,
}

// TrailerSize is the total size of the appended trailer:
// 8 bytes (offset) + 16 bytes (magic) = 24 bytes.
const TrailerSize = 24

// Pack walks srcDir and writes all files as a gzip-compressed tar stream to w.
// Paths in the archive are relative to srcDir (no leading slash, no srcDir prefix).
// Symlinks are followed. Empty directories are included as directory entries.
// Returns an error if any file cannot be read — no silent partial archives.
func Pack(srcDir string, w io.Writer) error {
	srcDir = filepath.Clean(srcDir)

	info, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot stat source directory %q: %w", srcDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("!!! FATAL: source %q is not a directory", srcDir)
	}

	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	err = filepath.Walk(srcDir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("!!! FATAL: walk error at %q: %w", path, walkErr)
		}

		// GRUG: Compute the archive-relative path. Strip srcDir prefix and
		// normalize to forward slashes so archives are cross-platform.
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot compute relative path for %q: %w", path, err)
		}
		rel = filepath.ToSlash(rel)

		// GRUG: Skip the root "." entry — it would extract as an empty dir entry
		// at the root and confuse the extractor.
		if rel == "." {
			return nil
		}

		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot build tar header for %q: %w", path, err)
		}
		hdr.Name = rel

		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("!!! FATAL: cannot write tar header for %q: %w", rel, err)
		}

		// GRUG: Only copy file contents for regular files.
		// Directories and symlinks only need headers.
		if fi.Mode().IsRegular() {
			f, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("!!! FATAL: cannot open %q for archiving: %w", path, err)
			}
			defer f.Close()

			if _, err := io.Copy(tw, f); err != nil {
				return fmt.Errorf("!!! FATAL: cannot archive file %q: %w", path, err)
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("!!! FATAL: cannot finalize tar stream: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("!!! FATAL: cannot finalize gzip stream: %w", err)
	}

	return nil
}

// Extract reads a gzip-compressed tar stream from r and writes all entries
// under destDir. Paths are sanitized to prevent directory traversal attacks
// (no "../" escapes, no absolute paths in archive entries).
// Returns an error if any entry cannot be extracted.
func Extract(r io.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("!!! FATAL: cannot create extract dir %q: %w", destDir, err)
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("!!! FATAL: corrupt tar stream: %w", err)
		}

		// GRUG: Sanitize path. Archive entries must not escape destDir.
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			return fmt.Errorf(
				"!!! FATAL: archive contains unsafe path %q — aborting extract", hdr.Name)
		}

		target := filepath.Join(destDir, clean)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, hdr.FileInfo().Mode()); err != nil {
				return fmt.Errorf("!!! FATAL: cannot create directory %q: %w", target, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			// GRUG: Ensure parent directory exists before writing the file.
			// Tar files don't guarantee directory entries appear before their children.
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("!!! FATAL: cannot create parent for %q: %w", target, err)
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, hdr.FileInfo().Mode())
			if err != nil {
				return fmt.Errorf("!!! FATAL: cannot create file %q: %w", target, err)
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("!!! FATAL: cannot write file %q: %w", target, err)
			}
			f.Close()

		default:
			// GRUG: Skip unknown entry types (symlinks etc.) with a warning.
			// We don't FATAL here because a missing symlink rarely breaks things,
			// but we don't silently swallow it either.
			fmt.Fprintf(os.Stderr, "[bindboss] warning: skipping archive entry %q (type %d)\n",
				hdr.Name, hdr.Typeflag)
		}
	}

	return nil
}

// AppendPayload appends a packed archive to an existing binary file at binPath.
// The layout written is:
//
//	[existing binary] [tar.gz data] [8-byte offset] [16-byte magic]
//
// The 8-byte offset records where the tar.gz data begins (= original file size).
// Returns the path of the output binary (same as binPath — modified in-place
// after writing to a temp file to avoid partial writes corrupting the input).
func AppendPayload(binPath string, srcDir string) error {
	// GRUG: Read the existing stub binary.
	stub, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot read stub binary %q: %w", binPath, err)
	}

	// GRUG: Write to a temp file first. If anything fails midway, the original
	// binary is untouched. Atomically replace at the end.
	tmp, err := os.CreateTemp(filepath.Dir(binPath), ".bindboss-pack-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot create temp file for packing: %w", err)
	}
	tmpPath := tmp.Name()

	defer func() {
		// GRUG: Clean up temp file if we exit before the atomic rename.
		os.Remove(tmpPath)
	}()

	// Write stub binary
	if _, err := tmp.Write(stub); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write stub to temp file: %w", err)
	}

	// Record where the tar.gz payload will start
	tarOffset := int64(len(stub))

	// Write tar.gz payload
	if err := Pack(srcDir, tmp); err != nil {
		tmp.Close()
		return err
	}

	// Write 8-byte big-endian offset
	var offsetBuf [8]byte
	binary.BigEndian.PutUint64(offsetBuf[:], uint64(tarOffset))
	if _, err := tmp.Write(offsetBuf[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write payload offset: %w", err)
	}

	// Write 16-byte magic trailer
	if _, err := tmp.Write(Magic[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write magic trailer: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("!!! FATAL: cannot flush packed binary: %w", err)
	}

	// GRUG: Atomic rename — replaces binPath with the fully packed temp file.
	if err := os.Rename(tmpPath, binPath); err != nil {
		return fmt.Errorf("!!! FATAL: cannot replace binary with packed version: %w", err)
	}

	// GRUG: Ensure output binary is executable.
	if err := os.Chmod(binPath, 0755); err != nil {
		return fmt.Errorf("!!! FATAL: cannot chmod packed binary: %w", err)
	}

	return nil
}

// FindPayload opens the binary at binPath, verifies the magic trailer,
// reads the tar.gz offset, and returns an io.ReadCloser positioned at the
// start of the tar.gz payload. Caller must Close() the reader.
//
// Returns an error (not nil reader) if the binary has no valid payload —
// this means it was not packed by bindboss and should not attempt extraction.
func FindPayload(binPath string) (io.ReadCloser, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot open binary %q: %w", binPath, err)
	}

	// GRUG: Seek to trailer position: last TrailerSize bytes.
	trailerPos, err := f.Seek(-TrailerSize, io.SeekEnd)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("!!! FATAL: binary too small to contain payload trailer: %w", err)
	}
	_ = trailerPos

	// Read 8-byte offset + 16-byte magic
	var trailer [TrailerSize]byte
	if _, err := io.ReadFull(f, trailer[:]); err != nil {
		f.Close()
		return nil, fmt.Errorf("!!! FATAL: cannot read payload trailer: %w", err)
	}

	// Verify magic
	var gotMagic [16]byte
	copy(gotMagic[:], trailer[8:])
	if gotMagic != Magic {
		f.Close()
		return nil, fmt.Errorf(
			"!!! FATAL: binary %q has no bindboss payload (magic mismatch) — " +
				"was this binary packed with 'bindboss pack'?", binPath)
	}

	// Read tar.gz start offset
	tarOffset := int64(binary.BigEndian.Uint64(trailer[:8]))

	// GRUG: Seek to tar.gz start and return a limited reader so the caller
	// can't accidentally read past the payload into the trailer.
	if _, err := f.Seek(tarOffset, io.SeekStart); err != nil {
		f.Close()
		return nil, fmt.Errorf("!!! FATAL: cannot seek to payload offset %d: %w", tarOffset, err)
	}

	// GRUG: Figure out tar.gz size = file_size - tarOffset - TrailerSize
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("!!! FATAL: cannot stat binary for payload size: %w", err)
	}
	payloadSize := fi.Size() - tarOffset - TrailerSize

	return &limitedReadCloser{r: io.LimitReader(f, payloadSize), c: f}, nil
}

// limitedReadCloser wraps a LimitReader and a Closer so FindPayload can
// return an io.ReadCloser that closes the underlying file.
type limitedReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l *limitedReadCloser) Close() error               { return l.c.Close() }