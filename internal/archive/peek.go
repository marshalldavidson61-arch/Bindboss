// peek.go
// =============================================================================
// GRUG: sometimes grug need to read just one file from the archive without
// extracting everything. like bindboss.toml. grug need it before grug know
// where to extract. chicken-and-egg problem. peek = solution.
//
// GRUG: peek reads tar.gz stream until it finds the requested file. returns
// the file content. doesn't write anything to disk. fast for small files.
//
// -----------------------------------------------------------------------------
// ACADEMIC FOOTER:
// ReadFileFromTarGz reads a tar.gz stream and returns the content of the
// first file matching the given name. It stops reading as soon as the file
// is found, making it efficient for small lookups in large archives.
// The reader is consumed and cannot be reused after this call.
// =============================================================================

package archive

import (
	"compress/gzip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"archive/tar"
)

// ReadFileFromTarGz reads a single file from a tar.gz stream by name.
// Returns the file content as bytes. The reader is consumed after this call.
// If the file is not found, returns an error.
//
// GRUG: name match is case-insensitive and strips leading "./" or "/" from
// both the archive entry name and the requested name. tar archives from
// different tools use different path conventions. normalize them.
func ReadFileFromTarGz(r io.Reader, fileName string) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot open gzip stream for peek: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)

	// GRUG: normalize the name we're looking for. strip ./ prefix and slashes.
	want := filepath.Clean(fileName)
	want = strings.TrimPrefix(want, "./")

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("!!! FATAL: corrupt tar stream during peek: %w", err)
		}

		// GRUG: normalize archive entry name same way.
		got := filepath.Clean(hdr.Name)
		got = strings.TrimPrefix(got, "./")

		if got == want && (hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA) {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("!!! FATAL: cannot read %q from archive: %w", fileName, err)
			}
			return data, nil
		}
	}

	return nil, fmt.Errorf("!!! FATAL: file %q not found in archive", fileName)
}