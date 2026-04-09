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
// reads the tar stream from that point, and extracts it.
//
// Trailer format (v2, 121 bytes):
//
//   [tar.gz data ...] [8b: tar offset BE] [32b: SHA-256 of tar bytes]
//   [64b: Ed25519 signature OR zeros] [1b: flags] [16b: magic v2]
//
// Flags byte:
//   bit 0 = hash present (always 1 in v2)
//   bit 1 = Ed25519 signature present
//
// Magic v2 differs from v1 so old stubs fail loudly on new binaries (correct).
// New stubs detect v1 magic and handle it gracefully (no hash/sig, run anyway).
//
// v1 trailer (legacy, read-only support): 24 bytes
//   [tar.gz data ...] [8b: tar offset BE] [16b: magic v1]
// =============================================================================

package archive

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// MagicV1 is the legacy 16-byte boundary marker (read-only support).
var MagicV1 = [16]byte{
	0xBB, 0x05, 0x5B, 0x0B, 0x1C, 0xEB, 0x05, 0x5B,
	0x0D, 0xEA, 0xDB, 0x0B, 0xBB, 0x0B, 0x05, 0x5B,
}

// MagicV2 is the v2 16-byte boundary marker.
// Differs from v1 at bytes [0] (0xBD vs 0xBB) and [15] (0x5C vs 0x5B),
// so v1 stubs FATAL loudly on v2 binaries rather than silently misreading.
var MagicV2 = [16]byte{
	0xBD, 0x05, 0x5B, 0x0B, 0x1C, 0xEB, 0x05, 0x5C,
	0x0D, 0xEA, 0xDB, 0x0B, 0xBB, 0x0B, 0x05, 0x5C,
}

// Magic is the current write magic (v2). Alias so call sites don't need
// version awareness when packing.
var Magic = MagicV2

// Trailer layout constants.
const (
	// TrailerV1Size: 8b offset + 16b magic = 24 bytes (legacy).
	TrailerV1Size = 24

	// TrailerV2Size: 8b offset + 32b hash + 64b sig + 1b flags + 16b magic = 121 bytes.
	// ACADEMIC: Ed25519 signatures are exactly 64 bytes. SHA-256 hashes are 32 bytes.
	// The flags byte records which optional fields are meaningful vs zero-filled.
	TrailerV2Size = 121

	// FlagHashPresent: bit 0 of flags — SHA-256 hash is valid (always set in v2).
	FlagHashPresent byte = 1 << 0

	// FlagSigPresent: bit 1 of flags — Ed25519 signature is valid.
	FlagSigPresent byte = 1 << 1
)

// TrailerSize is the size written by AppendPayload (always v2).
const TrailerSize = TrailerV2Size

// PayloadInfo is returned by FindPayload and carries the hash and sig
// alongside the reader, so callers (inspect, verify, stub) can use them
// without re-reading the file.
type PayloadInfo struct {
	// Reader is positioned at the start of the tar.gz payload.
	// Caller must Close() it.
	Reader io.ReadCloser

	// Hash is the SHA-256 of the raw tar.gz bytes (not the extracted content).
	// Zero-value if HashPresent is false (v1 binary).
	Hash [32]byte

	// Sig is the Ed25519 signature over Hash. Zero-value if SigPresent is false.
	Sig [64]byte

	// HashPresent is true if this is a v2 binary with a stored hash.
	HashPresent bool

	// SigPresent is true if this binary was packed with --sign.
	SigPresent bool

	// V1 is true if this binary uses the legacy v1 trailer format.
	// Provided for graceful degradation — no hash or sig available.
	V1 bool
}

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

// HashDir computes a deterministic SHA-256 digest of a directory tree.
//
// ACADEMIC: Determinism requires a canonical traversal order. We sort all
// file paths lexicographically, then hash each file as:
//
//	SHA-256.Write([]byte(rel_path + "\x00"))
//	SHA-256.Write(file_contents)
//
// Directory entries contribute only their path (no contents). This means
// two directories with identical files produce identical hashes regardless
// of filesystem ordering or metadata (mtime, inode, etc.).
func HashDir(dir string) ([32]byte, error) {
	type entry struct {
		rel  string
		path string
		isDir bool
	}

	var entries []entry
	err := filepath.Walk(dir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("!!! FATAL: walk error at %q: %w", path, walkErr)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot compute rel path for %q: %w", path, err)
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		entries = append(entries, entry{rel: rel, path: path, isDir: fi.IsDir()})
		return nil
	})
	if err != nil {
		return [32]byte{}, err
	}

	// GRUG: Sort by relative path for canonical order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rel < entries[j].rel
	})

	h := sha256.New()
	for _, e := range entries {
		// GRUG: Hash the path first (null-terminated for unambiguous framing).
		h.Write([]byte(e.rel + "\x00"))
		if !e.isDir {
			data, err := os.ReadFile(e.path)
			if err != nil {
				return [32]byte{}, fmt.Errorf("!!! FATAL: cannot read %q for hashing: %w", e.path, err)
			}
			h.Write(data)
		}
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// AppendPayload appends a packed archive to an existing binary file at binPath.
//
// The layout written is:
//
//	[existing binary] [tar.gz data] [8b: offset] [32b: SHA-256] [64b: sig or zeros]
//	[1b: flags] [16b: magic v2]
//
// privKey may be nil (no signature). Pass an ed25519.PrivateKey to sign.
// Returns an error on any failure — the original binary is never partially written.
func AppendPayload(binPath string, srcDir string, privKey ed25519.PrivateKey) error {
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

	// GRUG: Tee the pack output through a hash so we can record the SHA-256
	// of the raw compressed bytes without a second pass.
	payloadHasher := sha256.New()
	hw := &hashingWriter{w: tmp, h: payloadHasher}
	if err := Pack(srcDir, hw); err != nil {
		tmp.Close()
		return err
	}

	// Compute SHA-256 of payload bytes
	var payloadHash [32]byte
	copy(payloadHash[:], payloadHasher.Sum(nil))

	// Write 8-byte big-endian offset
	var offsetBuf [8]byte
	binary.BigEndian.PutUint64(offsetBuf[:], uint64(tarOffset))
	if _, err := tmp.Write(offsetBuf[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write payload offset: %w", err)
	}

	// Write 32-byte SHA-256 hash
	if _, err := tmp.Write(payloadHash[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write payload hash: %w", err)
	}

	// Write 64-byte signature (or zeros)
	var sig [64]byte
	flags := FlagHashPresent
	if privKey != nil {
		// ACADEMIC: Ed25519 signs the hash, not the raw payload. This is correct:
		// Sign(hash(message)) has the same security properties as Sign(message)
		// for collision-resistant hash functions, and avoids loading the full
		// payload into memory for signing.
		rawSig := ed25519.Sign(privKey, payloadHash[:])
		if len(rawSig) != 64 {
			tmp.Close()
			return fmt.Errorf("!!! FATAL: unexpected Ed25519 signature length %d", len(rawSig))
		}
		copy(sig[:], rawSig)
		flags |= FlagSigPresent
	}
	if _, err := tmp.Write(sig[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write signature: %w", err)
	}

	// Write 1-byte flags
	if _, err := tmp.Write([]byte{flags}); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write flags byte: %w", err)
	}

	// Write 16-byte magic v2 trailer
	if _, err := tmp.Write(MagicV2[:]); err != nil {
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

// FindPayload opens the binary at binPath, detects the trailer version,
// verifies the magic, reads the tar.gz offset, and returns a PayloadInfo
// with a reader positioned at the start of the tar.gz payload.
// Caller must Close() info.Reader.
//
// Returns a non-nil error (not a nil reader) if the binary has no valid
// payload — this means it was not packed by bindboss.
func FindPayload(binPath string) (*PayloadInfo, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot open binary %q: %w", binPath, err)
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("!!! FATAL: cannot stat binary %q: %w", binPath, err)
	}

	// GRUG: Try v2 trailer first (most common path). If magic doesn't match,
	// fall back to v1. If neither matches, the binary is not ours.
	info, err := tryReadV2Trailer(f, fi.Size())
	if err == nil {
		return info, nil
	}

	infoV1, errV1 := tryReadV1Trailer(f, fi.Size())
	if errV1 == nil {
		fmt.Fprintf(os.Stderr,
			"[bindboss] warning: binary %q uses legacy v1 format (no hash/sig) — consider repacking\n",
			binPath)
		return infoV1, nil
	}

	f.Close()
	return nil, fmt.Errorf(
		"!!! FATAL: binary %q has no bindboss payload (magic mismatch) — "+
			"was this binary packed with 'bindboss pack'?", binPath)
}

// HashPayload re-reads the raw tar.gz bytes from the binary and returns their
// SHA-256. Used by VerifyHash to detect tampering independently of the stored hash.
//
// ACADEMIC: We compare the re-computed hash against the stored hash in the
// trailer. A mismatch indicates either corruption or deliberate tampering.
// We recompute from first principles rather than trusting the stored value.
func HashPayload(binPath string) ([32]byte, error) {
	info, err := FindPayload(binPath)
	if err != nil {
		return [32]byte{}, err
	}
	defer info.Reader.Close()

	h := sha256.New()
	if _, err := io.Copy(h, info.Reader); err != nil {
		return [32]byte{}, fmt.Errorf("!!! FATAL: cannot hash payload in %q: %w", binPath, err)
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// VerifyHash re-computes the payload hash and compares it to the stored hash.
// Returns nil if they match, a descriptive error otherwise.
// Returns an error if the binary is v1 (no stored hash to compare against).
func VerifyHash(binPath string) error {
	f, err := os.Open(binPath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot open %q: %w", binPath, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("!!! FATAL: cannot stat %q: %w", binPath, err)
	}
	info, err := tryReadV2Trailer(f, fi.Size())
	f.Close()
	if err != nil {
		return fmt.Errorf("!!! FATAL: %q is not a v2 bindboss binary — cannot verify hash", binPath)
	}
	info.Reader.Close()

	if !info.HashPresent {
		return fmt.Errorf("!!! FATAL: binary %q has no stored hash", binPath)
	}

	computed, err := HashPayload(binPath)
	if err != nil {
		return err
	}

	if computed != info.Hash {
		return fmt.Errorf(
			"!!! FATAL: payload hash mismatch in %q — binary may be tampered or corrupt\n"+
				"  stored:   %x\n"+
				"  computed: %x",
			binPath, info.Hash, computed)
	}

	return nil
}

// VerifySig checks the Ed25519 signature in the binary against pubKey.
// Returns nil if valid, error if invalid or if no signature is present.
func VerifySig(binPath string, pubKey ed25519.PublicKey) error {
	f, err := os.Open(binPath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot open %q: %w", binPath, err)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("!!! FATAL: cannot stat %q: %w", binPath, err)
	}
	info, err := tryReadV2Trailer(f, fi.Size())
	f.Close()
	if err != nil {
		return fmt.Errorf("!!! FATAL: %q is not a v2 bindboss binary", binPath)
	}
	info.Reader.Close()

	if !info.SigPresent {
		return fmt.Errorf("!!! FATAL: binary %q was not signed", binPath)
	}

	if !ed25519.Verify(pubKey, info.Hash[:], info.Sig[:]) {
		return fmt.Errorf("!!! FATAL: Ed25519 signature verification FAILED for %q — "+
			"binary is tampered or signed with a different key", binPath)
	}

	return nil
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

// tryReadV2Trailer attempts to read a v2 trailer from f (size fileSize).
// Returns a PayloadInfo with an open reader on success, error otherwise.
func tryReadV2Trailer(f *os.File, fileSize int64) (*PayloadInfo, error) {
	if fileSize < int64(TrailerV2Size) {
		return nil, fmt.Errorf("file too small for v2 trailer")
	}

	if _, err := f.Seek(-int64(TrailerV2Size), io.SeekEnd); err != nil {
		return nil, fmt.Errorf("seek failed: %w", err)
	}

	var trailer [TrailerV2Size]byte
	if _, err := io.ReadFull(f, trailer[:]); err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	// Layout: [8b offset][32b hash][64b sig][1b flags][16b magic]
	// Offsets: 0..8, 8..40, 40..104, 104, 105..121
	var gotMagic [16]byte
	copy(gotMagic[:], trailer[105:121])
	if gotMagic != MagicV2 {
		return nil, fmt.Errorf("v2 magic mismatch")
	}

	tarOffset := int64(binary.BigEndian.Uint64(trailer[0:8]))
	var hashVal [32]byte
	copy(hashVal[:], trailer[8:40])
	var sig [64]byte
	copy(sig[:], trailer[40:104])
	flags := trailer[104]

	payloadSize := fileSize - tarOffset - int64(TrailerV2Size)
	if payloadSize < 0 {
		return nil, fmt.Errorf("!!! FATAL: v2 trailer offset %d produces negative payload size", tarOffset)
	}

	if _, err := f.Seek(tarOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot seek to payload offset %d: %w", tarOffset, err)
	}

	return &PayloadInfo{
		Reader:      &limitedReadCloser{r: io.LimitReader(f, payloadSize), c: f},
		Hash:        hashVal,
		Sig:         sig,
		HashPresent: flags&FlagHashPresent != 0,
		SigPresent:  flags&FlagSigPresent != 0,
		V1:          false,
	}, nil
}

// tryReadV1Trailer attempts to read the legacy v1 24-byte trailer.
func tryReadV1Trailer(f *os.File, fileSize int64) (*PayloadInfo, error) {
	if fileSize < int64(TrailerV1Size) {
		return nil, fmt.Errorf("file too small for v1 trailer")
	}

	if _, err := f.Seek(-int64(TrailerV1Size), io.SeekEnd); err != nil {
		return nil, fmt.Errorf("seek failed: %w", err)
	}

	var trailer [TrailerV1Size]byte
	if _, err := io.ReadFull(f, trailer[:]); err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	var gotMagic [16]byte
	copy(gotMagic[:], trailer[8:24])
	if gotMagic != MagicV1 {
		return nil, fmt.Errorf("v1 magic mismatch")
	}

	tarOffset := int64(binary.BigEndian.Uint64(trailer[0:8]))
	payloadSize := fileSize - tarOffset - int64(TrailerV1Size)
	if payloadSize < 0 {
		return nil, fmt.Errorf("v1 trailer offset produces negative payload size")
	}

	if _, err := f.Seek(tarOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("cannot seek to v1 payload offset: %w", err)
	}

	return &PayloadInfo{
		Reader: &limitedReadCloser{r: io.LimitReader(f, payloadSize), c: f},
		V1:     true,
	}, nil
}

// hashingWriter wraps an io.Writer and feeds all written bytes to a hash.Hash.
// Used in AppendPayload to hash the tar.gz bytes as they're written to disk,
// avoiding a second pass over the data.
type hashingWriter struct {
	w io.Writer
	h hash.Hash
}

func (hw *hashingWriter) Write(p []byte) (int, error) {
	n, err := hw.w.Write(p)
	if n > 0 {
		hw.h.Write(p[:n])
	}
	return n, err
}

// limitedReadCloser wraps a LimitReader and a Closer so FindPayload can
// return an io.ReadCloser that closes the underlying file.
type limitedReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l *limitedReadCloser) Close() error               { return l.c.Close() }