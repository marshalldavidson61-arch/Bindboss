// bindboss.go
// =============================================================================
// GRUG: This is the library cave. Other Go programs can import bindboss and
// call Pack/Inspect/Verify without shelling out to the CLI. No os.Args.
// No flag.Parse. No os.Exit. Just functions that return errors like a
// civilized Go library.
//
// If you are writing a build tool in Go (Bun plugin, Julia build script
// wrapper, CI system) and want to pack binaries programmatically — use this.
// If you just want to run `bindboss pack` from a terminal — use the CLI.
//
// Import path:
//   github.com/marshalldavidson61-arch/bindboss/pkg/bindboss
//
// Quick example:
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
//
// All exported functions return non-nil error on failure. No panics.
// No side effects other than filesystem writes (the output binary).
// No global state.
//
// ---
// ACADEMIC: The library API is a typed, minimal facade over the internal
// packages. Its design follows three principles:
//
//   1. No process lifecycle coupling:
//      Internal packages call fmt.Fprintf(os.Stderr) for logging but never
//      call os.Exit(). The library layer inherits this — callers retain full
//      control over process lifetime.
//
//   2. Type isomorphism with config.Config:
//      bb.Dep, bb.Hooks, and bb.PackOptions map 1:1 to config.Dep,
//      config.Hooks, and config.Config. The library re-exports these as
//      public types so callers do not need to import internal packages
//      (which are intentionally unexported by module convention).
//
//   3. Helper duplication over abstraction leakage:
//      compileStub, parseTarget, findModuleRoot, and copyDir are duplicated
//      from cmd/pack.go rather than shared via an internal helper package.
//      This keeps the cmd/ and pkg/ layers independently compilable and
//      avoids coupling the library's API surface to CLI implementation
//      details. The duplication is ~100 lines and changes rarely.
//
// Pack pipeline summary (same as CLI):
//   Stage 1: Compile stub binary (go build -tags stub, CGO_ENABLED=0)
//   Stage 2: Stage source dir + inject bindboss.toml
//   Stage 3: AppendPayload = tar.gz + 121-byte v2 trailer
//            (tar_offset || SHA-256 || Ed25519_or_zeros || flags || magic)
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
// SrcDir, OutPath, and Run are required. All other fields have safe zero values.
type PackOptions struct {
	// SrcDir is the directory to pack. Required.
	SrcDir string

	// OutPath is the output binary path. Required.
	OutPath string

	// Run is the command to execute inside the extracted directory. Required.
	// Example: "julia main.jl"
	Run string

	// ExecMode: "exec" (default) or "fork". See stub.go for exec model details.
	ExecMode string

	// Needs lists runtime dependencies to check on first run.
	Needs []Dep

	// Env lists extra environment variables injected before the run command.
	// Format: "KEY=value"
	Env []string

	// Hooks declares pre/post run commands.
	Hooks Hooks

	// Persist: if true, extract to a fixed directory and reuse on subsequent runs.
	Persist bool

	// ExtractDir overrides the extract root directory. Empty = use tmpdir.
	ExtractDir string

	// Target is the cross-compile target as "GOOS/GOARCH".
	// Empty = current platform.
	Target string

	// PrivKey is an optional Ed25519 private key for signing the payload.
	// nil = pack without signature (hash still stored in v2 trailer).
	PrivKey ed25519.PrivateKey
}

// Info describes the contents of a packed binary, returned by Inspect.
type Info struct {
	// Name is the binary name from embedded config.
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

	// Hash is the SHA-256 of the payload bytes as a hex string.
	// Empty if the binary is v1 format (no hash stored).
	Hash string

	// HashPresent is true if a hash is stored in the v2 trailer.
	HashPresent bool

	// SigPresent is true if an Ed25519 signature is stored in the v2 trailer.
	SigPresent bool

	// V1 is true if this binary uses the legacy v1 trailer format (no hash/sig).
	V1 bool
}

// Pack compiles a stub, stages the source directory, and writes the output binary.
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

	// GRUG: validate source dir exists and is actually a directory.
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

	// GRUG: stage source dir + inject bindboss.toml. never modify originals.
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

	// Compile stub for target platform
	goos, goarch, err := parseTarget(opts.Target)
	if err != nil {
		return err
	}

	outPath := opts.OutPath
	if goos == "windows" && !strings.HasSuffix(outPath, ".exe") {
		// GRUG: windows needs .exe. add it automatically.
		outPath += ".exe"
	}

	if err := compileStub(outPath, goos, goarch); err != nil {
		return err
	}

	// Append payload (tar.gz + v2 trailer with hash + optional sig)
	return archive.AppendPayload(outPath, tmpSrc, opts.PrivKey)
}

// Inspect reads a packed binary and returns its embedded configuration and
// trailer metadata. Does not extract permanently or execute anything.
// Returns a non-nil error if the binary is not a valid bindboss binary.
func Inspect(binPath string) (*Info, error) {
	payloadInfo, err := archive.FindPayload(binPath)
	if err != nil {
		return nil, err
	}
	defer payloadInfo.Reader.Close()

	// GRUG: extract to temp dir just to read bindboss.toml, then clean up.
	// nothing persists from an Inspect call.
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
		// GRUG: format as hex string so callers can display or compare easily.
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
	// GRUG: always check hash. sig check only if caller provides a key.
	if err := archive.VerifyHash(binPath); err != nil {
		return err
	}
	if pubKey != nil {
		return archive.VerifySig(binPath, pubKey)
	}
	return nil
}

// GenerateKey creates a new Ed25519 keypair and saves it to keyDir/<name>.key
// and keyDir/<name>.pub. Returns the private and public keys for immediate use.
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
// Internal helpers — mirror of cmd/pack.go, kept in sync manually.
// GRUG: duplication is intentional. see academic header for rationale.
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
		"CGO_ENABLED=0", // GRUG: static binary. no libc. works on any kernel.
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
	// GRUG: try executable dir first (installed), then cwd (go run / dev).
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