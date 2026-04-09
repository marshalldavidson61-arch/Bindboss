// pack.go
// =============================================================================
// GRUG: The pack command. Takes a directory and a binary name, compiles the
// stub for the target platform, appends the directory as a tar.gz payload,
// and writes the output binary. One command, done.
//
// ACADEMIC: The packing pipeline has three stages:
//   1. Compile the stub binary for the target platform (go build with GOOS/GOARCH).
//   2. Write the stub binary to the output path.
//   3. Append the packed directory + trailer to the output binary.
// The config (bindboss.toml or CLI flags) is written into the directory before
// archiving, so the stub finds it on extraction.
//
// v2 trailer: hash is always computed and stored. --sign=<keyfile> adds an
// Ed25519 signature over the payload hash for integrity invariant enforcement.
// =============================================================================

package cmd

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"crypto/ed25519"

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
	// GRUG: Go flag stops at first non-flag arg. Support any interleaving of
	// positionals and flags by separating them before parsing.
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
		return fmt.Errorf("!!! FATAL: %q is not a directory", srcDir)
	}

	// ------------------------------------------------------------------
	// Load and merge config
	// ------------------------------------------------------------------
	cfg, err := config.Load(srcDir)
	if err != nil {
		return err
	}

	// GRUG: Binary name = basename of output path, used in state files and logs.
	binaryName := filepath.Base(outPath)
	needsSlice := []string(c.needs)
	cfg, err = config.MergeFlags(cfg, binaryName, c.run, needsSlice, c.persist, c.dir)
	if err != nil {
		return err
	}

	// GRUG: Run command must be set either in toml or via --run flag.
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
	// Write merged config into source dir as bindboss.toml
	// GRUG: We write the config INTO a temp copy of the source dir so the
	// original directory is not modified. The stub reads it on extraction.
	// ------------------------------------------------------------------
	tmpSrc, err := os.MkdirTemp("", "bindboss-pack-src-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot create temp dir for pack staging: %w", err)
	}
	defer os.RemoveAll(tmpSrc)

	// GRUG: Copy source dir into tmpSrc so we can inject bindboss.toml.
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
		stubPath += ".exe"
		outPath = stubPath
	}

	if err := compileStub(stubPath, goos, goarch); err != nil {
		return err
	}

	// ------------------------------------------------------------------
	// Append payload to stub (with hash + optional sig)
	// ------------------------------------------------------------------
	fmt.Printf("[bindboss] packing %s into %s...\n", srcDir, outPath)
	if err := archive.AppendPayload(outPath, tmpSrc, privKey); err != nil {
		return err
	}

	// GRUG: Print final size so the user knows what they're shipping.
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
// Uses `go build` with the "stub" build tag so only stub.go is compiled.
func compileStub(outPath, goos, goarch string) error {
	// GRUG: Find the module root so we can tell go build where the stub package is.
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
		"CGO_ENABLED=0", // GRUG: Static binary. No libc dependency.
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
func findModuleRoot() (string, error) {
	// GRUG: First try the directory of the bindboss executable itself.
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

	// GRUG: Try the current working directory and its parents.
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
// destDir must already exist. Files are copied with their original permissions.
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