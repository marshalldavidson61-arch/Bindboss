// pack.go
// =============================================================================
// GRUG: The pack command. Grug give it a directory and an output name.
// Grug get back one binary that runs everywhere, no install needed.
// That is the whole deal. One command. One binary. Done.
//
// What happens inside:
//   1. Load bindboss.toml from source dir (if exists), merge with CLI flags
//   2. Copy source dir to a temp staging dir so originals stay untouched
//   3. Write merged config as bindboss.toml into the staging dir
//   4. Compile the stub binary for target platform (go build -tags stub)
//   5. Append staged dir as tar.gz + v2 trailer to the stub binary
//
// --run is required unless bindboss.toml already has a run field.
// --needs can be repeated for multiple deps.
// --sign adds an Ed25519 signature over the payload hash. Optional.
// --target lets grug cross-compile: --target=linux/amd64, darwin/arm64, etc.
//
// GRUG RULE: run command must be set. no run = no point. fatal error.
// GRUG RULE: source must be a directory. not a file. not a URL. a directory.
//
// ---
// ACADEMIC: The packing pipeline is a three-stage append-only construction:
//
//   Stage 1 — Stub compilation:
//     `go build -tags stub -o <output> ./stub` produces a statically linked
//     ELF/PE/Mach-O binary containing only the stub runtime. CGO_ENABLED=0
//     ensures portability — no libc dependency, runs on any kernel ABI version
//     for the target GOOS/GOARCH.
//
//   Stage 2 — Staging:
//     The source directory is copied into a temp dir and bindboss.toml is
//     injected with the merged configuration. This preserves the source tree
//     and ensures the stub finds a canonical config on extraction.
//
//   Stage 3 — Payload append (archive.AppendPayload):
//     The staged directory is compressed as tar.gz and appended to the stub
//     binary. A 121-byte v2 trailer is appended after the tar.gz:
//       [8b big-endian tar offset][32b SHA-256][64b Ed25519 or zeros][1b flags][16b magic]
//     SHA-256 is computed over the raw tar.gz bytes. If --sign is provided,
//     Ed25519 is computed over SHA-256(payload) — signing a hash rather than
//     raw bytes is safe when the hash function is collision-resistant (SHA-256
//     provides 128-bit collision resistance, well above the 80-bit threshold
//     for Ed25519 security).
//
//   Cross-compilation: GOOS and GOARCH are injected as environment variables
//   into the `go build` subprocess. The Go toolchain handles the rest.
//   The stub uses only syscall-level primitives (os, syscall, archive/tar,
//   compress/gzip) with no CGO, making cross-compilation reliable.
// =============================================================================

package cmd

import (
	"crypto/ed25519"
	"flag"
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

// PackCmd implements `bindboss pack`.
type PackCmd struct {
	fs      *flag.FlagSet
	run     string
	needs   multiFlag
	persist bool
	target  string // GOOS/GOARCH e.g. "linux/amd64"
	dir     string // extract dir override
	sign    string // path to .key file for Ed25519 signing
}

func NewPackCmd() *PackCmd {
	c := &PackCmd{fs: flag.NewFlagSet("pack", flag.ContinueOnError)}
	c.fs.StringVar(&c.run, "run", "", "command to run inside the packed directory (e.g. \"julia main.jl\")")
	c.fs.Var(&c.needs, "needs", "dependency: \"name,checkCmd,url\" or \"name,checkCmd,url,message\" (repeatable)")
	c.fs.BoolVar(&c.persist, "persist", false, "extract to a fixed directory instead of a fresh tmpdir each run")
	c.fs.StringVar(&c.target, "target", "", "cross-compile target as GOOS/GOARCH (default: current platform)")
	c.fs.StringVar(&c.dir, "dir", "", "override extract directory (default: ~/.bindboss/<name>/)")
	c.fs.StringVar(&c.sign, "sign", "", "path to Ed25519 private key file for payload signing (generated with `bindboss keygen`)")
	return c
}

func (c *PackCmd) Name() string { return "pack" }
func (c *PackCmd) Usage() string {
	return `pack <directory> <output> [flags]

  Pack a directory into a self-contained executable binary.

  Examples:
    bindboss pack ./myapp myapp --run="python main.py"
    bindboss pack ./grugbot grugbot --run="julia main.jl" --needs="julia,julia --version,https://julialang.org/downloads/"
    bindboss pack ./webapp webapp --run="bun run index.ts" --needs="bun,bun --version,https://bun.sh" --persist
    bindboss pack ./app app --run="./app" --sign=~/.bindboss/keys/mykey.key

  Flags:`
}

func (c *PackCmd) Run(args []string) error {
	// GRUG: Go flag.Parse stops at first non-flag arg. user might write:
	// "pack ./dir out --run=..." OR "pack --run=... ./dir out"
	// separate positionals from flags before parsing so both orderings work.
	var positionals, flagArgs []string
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
		} else {
			positionals = append(positionals, a)
		}
	}
	if err := c.fs.Parse(flagArgs); err != nil {
		return err
	}

	if len(positionals) < 2 {
		c.fs.Usage()
		return fmt.Errorf("!!! FATAL: pack requires <directory> and <output> arguments")
	}

	srcDir := positionals[0]
	outPath := positionals[1]

	// ------------------------------------------------------------------
	// Validate source directory
	// ------------------------------------------------------------------
	info, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("!!! FATAL: source directory %q: %w", srcDir, err)
	}
	if !info.IsDir() {
		// GRUG: not a directory = stop immediately. no partial packs.
		return fmt.Errorf("!!! FATAL: %q is not a directory", srcDir)
	}

	// ------------------------------------------------------------------
	// Load and merge config
	// ------------------------------------------------------------------
	cfg, err := config.Load(srcDir)
	if err != nil {
		return err
	}

	// GRUG: binary name = basename of output path. used in state files and logs.
	binaryName := filepath.Base(outPath)
	needsSlice := []string(c.needs)
	cfg, err = config.MergeFlags(cfg, binaryName, c.run, needsSlice, c.persist, c.dir)
	if err != nil {
		return err
	}

	// GRUG: validate after merge. run command must be set by now.
	if err := config.Validate(cfg); err != nil {
		return err
	}

	// ------------------------------------------------------------------
	// Load signing key if --sign was provided
	// ------------------------------------------------------------------
	var privKey ed25519.PrivateKey
	if c.sign != "" {
		privKey, err = keys.LoadPrivateKey(c.sign)
		if err != nil {
			return err
		}
		fmt.Printf("[bindboss] signing with key: %s\n", c.sign)
	}

	// ------------------------------------------------------------------
	// Stage source dir
	// GRUG: copy into temp dir, inject bindboss.toml. never modify originals.
	// ------------------------------------------------------------------
	tmpSrc, err := os.MkdirTemp("", "bindboss-pack-src-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot create temp dir for pack staging: %w", err)
	}
	defer os.RemoveAll(tmpSrc)

	if err := copyDir(srcDir, tmpSrc); err != nil {
		return fmt.Errorf("!!! FATAL: cannot copy source directory for staging: %w", err)
	}

	cfgBytes, err := config.ToTOML(cfg)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(tmpSrc, config.ConfigFileName)
	if err := os.WriteFile(cfgPath, cfgBytes, 0644); err != nil {
		return fmt.Errorf("!!! FATAL: cannot write bindboss.toml into staged directory: %w", err)
	}

	// ------------------------------------------------------------------
	// Compile stub for target platform
	// ------------------------------------------------------------------
	goos, goarch, err := parseTarget(c.target)
	if err != nil {
		return err
	}

	fmt.Printf("[bindboss] compiling stub for %s/%s...\n", goos, goarch)
	stubPath := outPath
	if goos == "windows" && !strings.HasSuffix(stubPath, ".exe") {
		// GRUG: windows binary needs .exe suffix or it won't run.
		stubPath += ".exe"
		outPath = stubPath
	}

	if err := compileStub(stubPath, goos, goarch); err != nil {
		return err
	}

	// ------------------------------------------------------------------
	// Append payload to stub
	// ------------------------------------------------------------------
	fmt.Printf("[bindboss] packing %s into %s...\n", srcDir, outPath)
	if err := archive.AppendPayload(outPath, tmpSrc, privKey); err != nil {
		return err
	}

	// GRUG: print size so user knows what they are shipping to someone.
	fi, _ := os.Stat(outPath)
	sizeMB := float64(0)
	if fi != nil {
		sizeMB = float64(fi.Size()) / (1024 * 1024)
	}
	fmt.Printf("[bindboss] ✓ packed: %s (%.1f MB)\n", outPath, sizeMB)
	fmt.Printf("[bindboss]   run command: %s\n", cfg.Run)
	if c.sign != "" {
		fmt.Printf("[bindboss]   signed: yes (Ed25519)\n")
	} else {
		fmt.Printf("[bindboss]   hash: yes (SHA-256, unsigned)\n")
	}
	if len(cfg.Needs) > 0 {
		fmt.Printf("[bindboss]   deps checked on first run:\n")
		for _, d := range cfg.Needs {
			fmt.Printf("[bindboss]     - %s (%s)\n", d.Name, d.Check)
		}
	}
	if len(cfg.Hooks.PreRun) > 0 {
		fmt.Printf("[bindboss]   pre_run hooks: %d\n", len(cfg.Hooks.PreRun))
	}
	if len(cfg.Hooks.PostRun) > 0 {
		fmt.Printf("[bindboss]   post_run hooks: %d (exec_mode=fork required on Unix)\n", len(cfg.Hooks.PostRun))
	}

	return nil
}

// compileStub compiles the stub binary to outPath for the given GOOS/GOARCH.
// Uses `go build -tags stub` so only stub.go (build tag "stub") is compiled.
func compileStub(outPath, goos, goarch string) error {
	// GRUG: find module root so we know where the stub package lives.
	// bindboss may be run from any directory, not just its source root.
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
		"CGO_ENABLED=0", // GRUG: static binary. no libc. runs on any kernel.
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("!!! FATAL: stub compilation failed for %s/%s: %w", goos, goarch, err)
	}
	return nil
}

// parseTarget splits a "GOOS/GOARCH" string. Empty target = current platform.
func parseTarget(target string) (goos, goarch string, err error) {
	if target == "" {
		// GRUG: no target = pack for right now, right here.
		return runtime.GOOS, runtime.GOARCH, nil
	}
	parts := strings.SplitN(target, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf(
			"!!! FATAL: --target must be GOOS/GOARCH (e.g. linux/amd64, darwin/arm64), got %q", target)
	}
	return parts[0], parts[1], nil
}

// findModuleRoot walks up from the current directory to find go.mod.
// Tries the directory of the bindboss executable first, then cwd.
func findModuleRoot() (string, error) {
	// GRUG: try from the executable's dir first. most reliable when installed.
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

	// GRUG: fall back to cwd walk. works when running `go run .` from source.
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

// copyDir recursively copies srcDir into destDir.
// destDir must already exist. Files are copied with original permissions.
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

// multiFlag is a flag.Value that accumulates multiple --needs flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}