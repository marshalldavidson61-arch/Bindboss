// inspect.go
// =============================================================================
// GRUG: The inspect command. Grug want to know what is inside a packed binary
// before running it. What does it run? What deps does it check? Is it signed?
// `bindboss inspect ./grugbot` answers all of that without executing anything.
//
// Inspect is read-only. It extracts to a temp dir, reads bindboss.toml,
// prints everything, and cleans up. Nothing executes. Nothing persists.
// Safe to run on any bindboss binary, even untrusted ones.
//
// --list flag shows every file in the packed archive. Useful to confirm
// the right files were included and nothing was accidentally left out.
//
// ---
// ACADEMIC: Inspect performs a non-destructive read of the binary's payload:
//
//   1. archive.FindPayload seeks to the v2 (or v1) trailer to locate the
//      tar offset and read metadata (hash, sig flags) without extracting.
//   2. archive.Extract unpacks the tar.gz into a fresh os.MkdirTemp directory.
//   3. config.Load reads bindboss.toml from the extracted directory.
//   4. The temp directory is removed via defer os.RemoveAll.
//
// No state is written. No hooks are run. The binary itself is opened read-only.
// The extraction is purely for config parsing — bindboss.toml is the only
// file consulted from the payload during inspect.
//
// v1 binaries (24-byte trailer, no hash/sig) are handled transparently —
// FindPayload returns V1=true and HashPresent=false; inspect prints the
// format version accordingly so users know to repack for v2 features.
// =============================================================================

package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/marshalldavidson61-arch/bindboss/internal/archive"
	"github.com/marshalldavidson61-arch/bindboss/internal/config"
)

// InspectCmd implements `bindboss inspect`.
type InspectCmd struct {
	fs      *flag.FlagSet
	listAll bool
}

func NewInspectCmd() *InspectCmd {
	c := &InspectCmd{fs: flag.NewFlagSet("inspect", flag.ContinueOnError)}
	c.fs.BoolVar(&c.listAll, "list", false, "list all files in the packed archive")
	return c
}

func (c *InspectCmd) Name() string { return "inspect" }
func (c *InspectCmd) Usage() string {
	return `inspect <binary> [flags]

  Print the configuration and dependency list embedded in a packed binary.
  Does not execute anything. Safe on untrusted binaries.

  Examples:
    bindboss inspect ./grugbot
    bindboss inspect ./myapp --list

  Flags:`
}

func (c *InspectCmd) Run(args []string) error {
	// GRUG: same positional/flag separation as pack. binary path is positional.
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
	if len(positionals) < 1 {
		return fmt.Errorf("!!! FATAL: inspect requires a binary path — usage: bindboss inspect <binary>")
	}

	binPath := positionals[0]

	// GRUG: resolve to absolute path for clean display in output.
	absPath, err := filepath.Abs(binPath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot resolve binary path %q: %w", binPath, err)
	}

	// ------------------------------------------------------------------
	// Find payload — get PayloadInfo for hash/sig metadata
	// ------------------------------------------------------------------
	payloadInfo, err := archive.FindPayload(absPath)
	if err != nil {
		return err
	}
	defer payloadInfo.Reader.Close()

	// ------------------------------------------------------------------
	// Extract to temp dir for config reading
	// GRUG: temp dir deleted on return. nothing persists from inspect.
	// ------------------------------------------------------------------
	tmpDir, err := os.MkdirTemp("", "bindboss-inspect-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot create inspect tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := archive.Extract(payloadInfo.Reader, tmpDir); err != nil {
		return err
	}

	cfg, err := config.Load(tmpDir)
	if err != nil {
		return err
	}

	// ------------------------------------------------------------------
	// Print config summary
	// ------------------------------------------------------------------
	fmt.Printf("binary:    %s\n", binPath)
	fmt.Printf("name:      %s\n", cfg.Name)
	fmt.Printf("run:       %s\n", cfg.Run)
	fmt.Printf("exec_mode: %s\n", cfg.ExecMode)

	// GRUG: show format version and integrity status upfront.
	// v1 = legacy, no hash. v2 = has hash, may have sig.
	if payloadInfo.V1 {
		fmt.Printf("format:    v1 (legacy — no hash/sig)\n")
	} else {
		fmt.Printf("format:    v2\n")
		if payloadInfo.HashPresent {
			fmt.Printf("hash:      %x\n", payloadInfo.Hash)
		}
		if payloadInfo.SigPresent {
			fmt.Printf("signed:    yes (Ed25519)\n")
		} else {
			fmt.Printf("signed:    no\n")
		}
	}

	if len(cfg.Env) > 0 {
		fmt.Printf("env:\n")
		for _, kv := range cfg.Env {
			fmt.Printf("  %s\n", kv)
		}
	}

	if len(cfg.Needs) > 0 {
		fmt.Printf("deps:\n")
		for _, d := range cfg.Needs {
			fmt.Printf("  - %s\n", d.Name)
			fmt.Printf("    check:   %s\n", d.Check)
			fmt.Printf("    url:     %s\n", d.URL)
			if d.Message != "" {
				fmt.Printf("    message: %s\n", d.Message)
			}
		}
	} else {
		fmt.Printf("deps:      (none)\n")
	}

	if len(cfg.Hooks.PreRun) > 0 {
		fmt.Printf("pre_run hooks:\n")
		for i, h := range cfg.Hooks.PreRun {
			fmt.Printf("  [%d] %s\n", i, h)
		}
	}
	if len(cfg.Hooks.PostRun) > 0 {
		fmt.Printf("post_run hooks:\n")
		for i, h := range cfg.Hooks.PostRun {
			fmt.Printf("  [%d] %s\n", i, h)
		}
	}

	fmt.Printf("persist:   %v\n", cfg.Extract.Persist)
	if cfg.Extract.Dir != "" {
		fmt.Printf("dir:       %s\n", cfg.Extract.Dir)
	}

	if cfg.Update.URL != "" {
		fmt.Printf("update:    %s", cfg.Update.URL)
		if cfg.Update.Branch != "" {
			fmt.Printf(" (branch: %s)", cfg.Update.Branch)
		}
		fmt.Println()
	}

	// ------------------------------------------------------------------
	// File listing (--list only)
	// ------------------------------------------------------------------
	if c.listAll {
		fmt.Printf("\nfiles:\n")
		err = filepath.Walk(tmpDir, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, _ := filepath.Rel(tmpDir, path)
			if rel == "." {
				// GRUG: skip root entry. not useful in listing.
				return nil
			}
			if fi.IsDir() {
				fmt.Printf("  %s/\n", rel)
			} else {
				fmt.Printf("  %s (%d bytes)\n", rel, fi.Size())
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("!!! FATAL: cannot list archive contents: %w", err)
		}
	}

	return nil
}