// archive.go
// =============================================================================
// GRUG: grug pack directory into one blob. blob go at end of binary.
// binary run, binary find blob at end, binary pull out files, binary run command.
// grug not need install. grug not need package manager. grug just run file.
//
// GRUG: blob has magic number at very end so grug can find it fast.
// grug seek to end of file, read 121 bytes, check magic. if magic wrong,
// not a bindboss binary. FATAL. no silent fail ever.
//
// GRUG: new binary (v2) also store hash of blob. if someone mess with blob,
// hash not match. FATAL. old binary (v1) still work but grug warn you.
//
// GRUG: signing optional. if you give key, grug sign hash with Ed25519.
// now even if attacker swap payload, signature break. caught.
//
// -----------------------------------------------------------------------------
// ACADEMIC FOOTER:
// The self-extracting binary pattern appends a gzip-compressed tar archive to
// a valid ELF/Mach-O/PE executable. The OS loader reads only the ELF headers
// at the binary's front; the appended payload is invisible to it. The stub
// then locates the payload via a fixed-size trailer at EOF.
//
// Trailer layout (v2, 121 bytes):
//   [tar.gz bytes ...][8b offset BE][32b SHA-256][64b Ed25519 or zeros][1b flags][16b magic]
//
// The 8-byte offset is a big-endian uint64 recording where the tar.gz data
// begins (= original stub size). This gives O(1) payload location with no
// scanning. SHA-256 covers the raw compressed bytes. Ed25519 signs the hash
// (not the raw payload), which is safe for collision-resistant hash functions
// and avoids loading the full payload for signing.
//
// Flags byte: bit 0 = hash present (always 1 in v2), bit 1 = sig present.
//
// v1 trailer (24 bytes, legacy): [8b offset][16b magic v1]. Detected at
// runtime; new stub reads it gracefully, warns, and runs. v1 magic differs
// from v2 magic so old stubs FATAL loudly on new binaries — correct behavior.
//
// HashDir uses a canonical sorted traversal (lexicographic by relative path)
// feeding SHA-256 as: Write(relpath+"\x00") then Write(file_contents) per
// entry. Metadata (mtime, inode, permissions) is intentionally excluded so
// two directories with identical content hash identically.
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

// MagicV1 is the legacy 16-byte trailer marker. Read-only — grug no longer writes this.
var MagicV1 = [16]byte{
	0xBB, 0x05, 0x5B, 0x0B, 0x1C, 0xEB, 0x05, 0x5B,
	0x0D, 0xEA, 0xDB, 0x0B, 0xBB, 0x0B, 0x05, 0x5B,
}

// MagicV2 is the current 16-byte trailer marker.
// Byte [0] and [15] differ from v1 — old stubs see wrong magic and FATAL loudly.
var MagicV2 = [16]byte{
	0xBD, 0x05, 0x5B, 0x0B, 0x1C, 0xEB, 0x05, 0x5C,
	0x0D, 0xEA, 0xDB, 0x0B, 0xBB, 0x0B, 0x05, 0x5C,
}

// Magic is what grug writes. Always v2.
var Magic = MagicV2

const (
	TrailerV1Size = 24  // v1: 8b offset + 16b magic
	TrailerV2Size = 121 // v2: 8b offset + 32b hash + 64b sig + 1b flags + 16b magic

	FlagHashPresent byte = 1 << 0 // bit 0: SHA-256 stored (always 1 in v2)
	FlagSigPresent  byte = 1 << 1 // bit 1: Ed25519 signature stored
)

// TrailerSize is what grug writes today.
const TrailerSize = TrailerV2Size

// PayloadInfo is what FindPayload hands back.
// Carry it around — it has the reader AND the hash AND sig status.
type PayloadInfo struct {
	Reader      io.ReadCloser // positioned at start of tar.gz — caller must Close()
	Hash        [32]byte      // SHA-256 of tar.gz bytes. zero if V1
	Sig         [64]byte      // Ed25519 sig over Hash. zero if not signed
	HashPresent bool          // true for v2 binaries
	SigPresent  bool          // true if packed with --sign
	V1          bool          // true for legacy binaries — no hash, no sig
}

// Pack walks srcDir and writes everything as gzip tar into w.
// Paths inside archive are relative to srcDir. No srcDir prefix. No leading slash.
// Empty dirs included. Symlinks followed. Any read error = FATAL. No partial archives.
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

		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot compute relative path for %q: %w", path, err)
		}
		rel = filepath.ToSlash(rel)

		// GRUG: skip root "." — would make empty dir entry at root, confuse extractor
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

		// GRUG: only copy bytes for real files. dirs and symlinks just need header.
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

// Extract pulls a gzip tar stream from r and writes files under destDir.
// Sanitizes paths — no "../" escapes, no absolute paths. Any bad path = FATAL.
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

		// GRUG: bad path = attacker tries to escape destDir. kill it.
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
			// GRUG: tar does not guarantee dir entries before child files. make parent anyway.
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
			// GRUG: unknown type (symlinks etc) — skip with warning, not FATAL.
			// missing symlink rarely breaks things. silent skip is still wrong so we warn.
			fmt.Fprintf(os.Stderr, "[bindboss] warning: skipping archive entry %q (type %d)\n",
				hdr.Name, hdr.Typeflag)
		}
	}

	return nil
}

// HashDir computes a deterministic SHA-256 of a whole directory tree.
// Same files + same names = same hash, always, regardless of filesystem order.
func HashDir(dir string) ([32]byte, error) {
	type entry struct {
		rel   string
		path  string
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

	// GRUG: sort by path so hash is same no matter what order filesystem returns files
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rel < entries[j].rel
	})

	h := sha256.New()
	for _, e := range entries {
		// GRUG: null byte after path = unambiguous framing. no two paths can collide.
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

// AppendPayload writes stub + tar.gz + v2 trailer into binPath atomically.
// privKey may be nil — grug skip signature, store zeros in sig field.
// Original binary never touched if anything fails — temp file + rename.
func AppendPayload(binPath string, srcDir string, privKey ed25519.PrivateKey) error {
	stub, err := os.ReadFile(binPath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot read stub binary %q: %w", binPath, err)
	}

	// GRUG: write to temp file first. if crash midway, original binary still good.
	tmp, err := os.CreateTemp(filepath.Dir(binPath), ".bindboss-pack-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot create temp file for packing: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // GRUG: clean up temp if rename never happens

	if _, err := tmp.Write(stub); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write stub to temp file: %w", err)
	}

	tarOffset := int64(len(stub))

	// GRUG: tee pack output through hasher — get hash without second pass over data
	payloadHasher := sha256.New()
	hw := &hashingWriter{w: tmp, h: payloadHasher}
	if err := Pack(srcDir, hw); err != nil {
		tmp.Close()
		return err
	}

	var payloadHash [32]byte
	copy(payloadHash[:], payloadHasher.Sum(nil))

	// write 8-byte offset
	var offsetBuf [8]byte
	binary.BigEndian.PutUint64(offsetBuf[:], uint64(tarOffset))
	if _, err := tmp.Write(offsetBuf[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write payload offset: %w", err)
	}

	// write 32-byte SHA-256
	if _, err := tmp.Write(payloadHash[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write payload hash: %w", err)
	}

	// write 64-byte sig or zeros
	var sig [64]byte
	flags := FlagHashPresent
	if privKey != nil {
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

	// write 1-byte flags
	if _, err := tmp.Write([]byte{flags}); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write flags byte: %w", err)
	}

	// write 16-byte magic
	if _, err := tmp.Write(MagicV2[:]); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write magic trailer: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("!!! FATAL: cannot flush packed binary: %w", err)
	}

	// GRUG: atomic rename — binPath either fully replaced or untouched. no half-writes.
	if err := os.Rename(tmpPath, binPath); err != nil {
		return fmt.Errorf("!!! FATAL: cannot replace binary with packed version: %w", err)
	}

	if err := os.Chmod(binPath, 0755); err != nil {
		return fmt.Errorf("!!! FATAL: cannot chmod packed binary: %w", err)
	}

	return nil
}

// FindPayload opens binPath, sniffs trailer version, and returns PayloadInfo
// with reader positioned at start of tar.gz. Caller must Close() reader.
// Returns FATAL error — not nil reader — if binary has no bindboss payload.
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

	// GRUG: try v2 first (normal path). fall back to v1. if both fail = not ours.
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

// HashPayload re-reads the raw tar.gz bytes from the binary and returns their SHA-256.
// Independent of the stored hash — used to detect tampering from first principles.
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

// VerifyHash re-computes payload hash and compares to stored value.
// Returns FATAL error on mismatch. Returns FATAL if binary is v1 (no stored hash).
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

// VerifySig checks the Ed25519 signature against pubKey.
// Returns FATAL if no sig present or if sig is invalid.
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
// internal helpers
// -----------------------------------------------------------------------------

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

	// layout: [8b offset][32b hash][64b sig][1b flags][16b magic]
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

// hashingWriter tees all writes through a hash.Hash without extra copying.
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

// limitedReadCloser wraps LimitReader + Closer so FindPayload returns io.ReadCloser.
type limitedReadCloser struct {
	r io.Reader
	c io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (int, error) { return l.r.Read(p) }
func (l *limitedReadCloser) Close() error               { return l.c.Close() }