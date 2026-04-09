// bindboss.go
// =============================================================================
// GRUG: This is the library cave. Exposes bindboss as an importable Go package
// so Bun/Julia build tools and other Go programs can call it programmatically
// without shelling out to the CLI.
//
// ACADEMIC: The library API is a thin, typed wrapper over the internal packages.
// It avoids os.Exit and flag parsing entirely — those belong to the CLI layer.
// All errors are returned as values. Callers decide what to do with them.
//
// Import path: github.com/marshalldavidson61-arch/bindboss/pkg/bindboss
//
// Minimal example:
//
//   import bb "github.com/marshalldavidson61-arch/bindboss/pkg/bindboss"
//
//   err := bb.Pack(bb.PackOptions{
//       SrcDir:  "./myapp",
//       OutPath: "./myapp-bin",
//       Run:     "julia main.jl",
//       Needs: []bb.Dep{{
//           Name:  "julia",
//           Check: "julia --version",
//           URL:   "https://julialang.org/downloads/",
//       }},
//   })
// =============================================================================

package bindboss

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marshalldavidson61-arch/bindboss/internal/archive"
	"github.com/marshalldavidson61-arch/bindboss/internal/config"
	"github.com/marshalldavidson61-arch/bindboss/internal/keys"
)

// Dep describes a runtime dependency for programmatic use.
// Maps 1:1 to config.Dep.
type Dep struct {
	Name    string
	Check   string
	URL     string
	Message string
}

// Hooks declares pre/post run hook commands for programmatic use.
type Hooks struct {
	PreRun  []string
	PostRun []string
}

// PackOptions holds all parameters for a Pack call.
// All fields except SrcDir, OutPath, and Run have safe zero values.
type PackOptions struct {
	// SrcDir is the directory to pack. Required.
	SrcDir string

	// OutPath is the output binary path. Required.
	OutPath string

	// Run is the command to execute inside the extracted directory. Required.
	// Example: "julia main.jl"
	Run string

	// ExecMode: "exec" (default) or "fork". See config.Config.ExecMode.
	ExecMode string

	// Needs lists runtime dependencies to check on first run.
	Needs []Dep

	// Env lists extra environment variables for the run command.
	// Format: "KEY=value"
	Env []string

	// Hooks declares pre/post run commands.
	Hooks Hooks

	// Persist: if true, extract to a fixed directory and reuse on subsequent runs.
	Persist bool

	// ExtractDir overrides the extract root directory.
	ExtractDir string

	// Target is the cross-compile target as "GOOS/GOARCH".
	// Empty = current platform.
	Target string

	// PrivKey is an optional Ed25519 private key for signing the payload.
	// nil = no signature.
	PrivKey ed25519.PrivateKey
}

// Info describes the contents of a packed binary, returned by Inspect.
type Info struct {
	// Name is the binary name from config.
	Name string

	// Run is the run command embedded in the binary.
	Run string

	// ExecMode is "exec" or "fork".
	ExecMode string

	// Needs is the list of runtime dependencies.
	Needs []Dep

	// Env is the list of extra environment variables.
	Env []string

	// Hooks is the pre/post run hook configuration.
	Hooks Hooks

	// Hash is the SHA-256 of the payload bytes (hex string).
	// Empty if the binary is v1 (no hash stored).
	Hash string

	// HashPresent is true if a hash is stored in the trailer.
	HashPresent bool

	// SigPresent is true if an Ed25519 signature is stored in the trailer.
	SigPresent bool

	// V1 is true if this binary uses the legacy v1 trailer format.
	V1 bool
}

// Pack compiles a stub, packs the directory, and writes the output binary.
// This is the programmatic equivalent of `bindboss pack`.
// Returns a non-nil error on any failure — no silent partial output.
func Pack(opts PackOptions) error {
	if opts.SrcDir == "" {
		return fmt.Errorf("!!! FATAL: Pack: SrcDir is required")
	}
	if opts.OutPath == "" {
		return fmt.Errorf("!!! FATAL: Pack: OutPath is required")
	}
	if opts.Run == "" {
		return fmt.Errorf("!!! FATAL: Pack: Run command is required")
	}

	// GRUG: Validate source directory exists and is a directory.
	info, err := os.Stat(opts.SrcDir)
	if err != nil {
		return fmt.Errorf("!!! FATAL: Pack: source directory %q: %w", opts.SrcDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("!!! FATAL: Pack: %q is not a directory", opts.SrcDir)
	}

	// Build config from options
	cfg := config.DefaultConfig()
	cfg.Name = filepath.Base(opts.OutPath)
	cfg.Run = opts.Run
	if opts.ExecMode != "" {
		cfg.ExecMode = opts.ExecMode
	}
	cfg.Env = opts.Env
	cfg.Extract.Persist = opts.Persist
	if opts.ExtractDir != "" {
		cfg.Extract.Dir = opts.ExtractDir
	}
	cfg.Hooks.PreRun = opts.Hooks.PreRun
	cfg.Hooks.PostRun = opts.Hooks.PostRun

	for _, d := range opts.Needs {
		cfg.Needs = append(cfg.Needs, config.Dep{
			Name:    d.Name,
			Check:   d.Check,
			URL:     d.URL,
			Message: d.Message,
		})
	}

	if err := config.Validate(cfg); err != nil {
		return err
	}

	// Stage source dir with injected bindboss.toml
	tmpSrc, err := os.MkdirTemp("", "bindboss-pack-src-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: Pack: cannot create temp staging dir: %w", err)
	}
	defer os.RemoveAll(tmpSrc)

	if err := copyDir(opts.SrcDir, tmpSrc); err != nil {
		return fmt.Errorf("!!! FATAL: Pack: cannot copy source dir for staging: %w", err)
	}

	cfgBytes, err := config.ToTOML(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmpSrc, config.ConfigFileName), cfgBytes, 0644); err != nil {
		return fmt.Errorf("!!! FATAL: Pack: cannot write bindboss.toml to staging dir: %w", err)
	}

	// Compile stub
	goos, goarch, err := parseTarget(opts.Target)
	if err != nil {
		return err
	}

	outPath := opts.OutPath
	if goos == "windows" && !strings.HasSuffix(outPath, ".exe") {
		outPath += ".exe"
	}

	if err := compileStub(outPath, goos, goarch); err != nil {
		return err
	}

	// Append payload
	return archive.AppendPayload(outPath, tmpSrc, opts.PrivKey)
}

// Inspect reads a packed binary and returns its embedded configuration and
// trailer metadata. Does not extract or execute anything.
// Returns a non-nil error if the binary is not a valid bindboss binary.
func Inspect(binPath string) (*Info, error) {
	payloadInfo, err := archive.FindPayload(binPath)
	if err != nil {
		return nil, err
	}
	defer payloadInfo.Reader.Close()

	// GRUG: Extract to a temp dir just to read bindboss.toml, then clean up.
	tmpDir, err := os.MkdirTemp("", "bindboss-inspect-*")
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: Inspect: cannot create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := archive.Extract(payloadInfo.Reader, tmpDir); err != nil {
		return nil, fmt.Errorf("!!! FATAL: Inspect: cannot extract payload: %w", err)
	}

	cfg, err := config.Load(tmpDir)
	if err != nil {
		return nil, err
	}

	var needs []Dep
	for _, d := range cfg.Needs {
		needs = append(needs, Dep{
			Name:    d.Name,
			Check:   d.Check,
			URL:     d.URL,
			Message: d.Message,
		})
	}

	hashHex := ""
	if payloadInfo.HashPresent {
		hashHex = fmt.Sprintf("%x", payloadInfo.Hash)
	}

	return &Info{
		Name:        cfg.Name,
		Run:         cfg.Run,
		ExecMode:    cfg.ExecMode,
		Needs:       needs,
		Env:         cfg.Env,
		Hooks:       Hooks{PreRun: cfg.Hooks.PreRun, PostRun: cfg.Hooks.PostRun},
		Hash:        hashHex,
		HashPresent: payloadInfo.HashPresent,
		SigPresent:  payloadInfo.SigPresent,
		V1:          payloadInfo.V1,
	}, nil
}

// Verify checks the payload hash of the binary. If pubKey is non-nil, also
// verifies the Ed25519 signature. Returns nil on success, error on failure.
// Equivalent to `bindboss verify` (with optional --pubkey).
func Verify(binPath string, pubKey ed25519.PublicKey) error {
	if err := archive.VerifyHash(binPath); err != nil {
		return err
	}
	if pubKey != nil {
		return archive.VerifySig(binPath, pubKey)
	}
	return nil
}

// GenerateKey creates a new Ed25519 keypair and saves it to keyDir/<name>.key
// and keyDir/<name>.pub. Returns the private key for immediate use.
// If keyDir is empty, uses the default (~/.bindboss/keys/).
func GenerateKey(keyDir, name string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if keyDir == "" {
		var err error
		keyDir, err = keys.DefaultKeyDir()
		if err != nil {
			return nil, nil, err
		}
	}
	kp, err := keys.Generate(keyDir, name)
	if err != nil {
		return nil, nil, err
	}
	return kp.PrivateKey, kp.PublicKey, nil
}

// LoadPrivateKey loads an Ed25519 private key from a PEM file.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	return keys.LoadPrivateKey(path)
}

// LoadPublicKey loads an Ed25519 public key from a PEM file.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	return keys.LoadPublicKey(path)
}

// -----------------------------------------------------------------------------
// Internal helpers (mirror of cmd/pack.go — kept in sync)
// -----------------------------------------------------------------------------

func compileStub(outPath, goos, goarch string) error {
	moduleRoot, err := findModuleRoot()
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot find bindboss module root: %w", err)
	}

	stubPkg := filepath.Join(moduleRoot, "stub")
	cmd := exec.Command("go", "build",
		"-tags", "stub",
		"-o", outPath,
		stubPkg,
	)
	cmd.Env = append(os.Environ(),
		"GOOS="+goos,
		"GOARCH="+goarch,
		"CGO_ENABLED=0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("!!! FATAL: stub compilation failed for %s/%s: %w", goos, goarch, err)
	}
	return nil
}

func parseTarget(target string) (goos, goarch string, err error) {
	if target == "" {
		return runtime.GOOS, runtime.GOARCH, nil
	}
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf(
			"!!! FATAL: target must be GOOS/GOARCH (e.g. linux/amd64), got %q", target)
	}
	return parts[0], parts[1], nil
}

func findModuleRoot() (string, error) {
	self, err := os.Executable()
	if err == nil {
		self, _ = filepath.EvalSymlinks(self)
		dir := filepath.Dir(self)
		for {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot get cwd: %w", err)
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("go.mod not found — bindboss must be run from its source directory")
}

func copyDir(srcDir, destDir string) error {
	return filepath.Walk(srcDir, func(path string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("!!! FATAL: walk error during copy at %q: %w", path, walkErr)
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot compute rel path during copy: %w", err)
		}
		target := filepath.Join(destDir, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, fi.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot read %q during copy: %w", path, err)
		}
		return os.WriteFile(target, data, fi.Mode())
	})
}