// inspect.go
// =============================================================================
// GRUG: The inspect command. Reads the payload from a packed binary and prints
// its config — run command, deps, extract settings. Useful to verify what a
// binary will do before running it, or to debug a pack that isn't working.
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

  Examples:
    bindboss inspect ./grugbot
    bindboss inspect ./myapp --list

  Flags:`
}

func (c *InspectCmd) Run(args []string) error {
	// GRUG: Separate positionals from flags before parsing (same as pack).
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

	// GRUG: Resolve the binary path.
	absPath, err := filepath.Abs(binPath)
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot resolve binary path %q: %w", binPath, err)
	}

	// ------------------------------------------------------------------
	// Extract to a temp dir so we can read the config
	// ------------------------------------------------------------------
	payloadReader, err := archive.FindPayload(absPath)
	if err != nil {
		return err
	}
	defer payloadReader.Close()

	tmpDir, err := os.MkdirTemp("", "bindboss-inspect-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot create inspect tmpdir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := archive.Extract(payloadReader, tmpDir); err != nil {
		return err
	}

	cfg, err := config.Load(tmpDir)
	if err != nil {
		return err
	}

	// ------------------------------------------------------------------
	// Print config
	// ------------------------------------------------------------------
	fmt.Printf("binary:  %s\n", binPath)
	fmt.Printf("name:    %s\n", cfg.Name)
	fmt.Printf("run:     %s\n", cfg.Run)

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
		fmt.Printf("deps:    (none)\n")
	}

	fmt.Printf("persist: %v\n", cfg.Extract.Persist)
	if cfg.Extract.Dir != "" {
		fmt.Printf("dir:     %s\n", cfg.Extract.Dir)
	}

	// ------------------------------------------------------------------
	// List files if requested
	// ------------------------------------------------------------------
	if c.listAll {
		fmt.Printf("\nfiles:\n")
		err = filepath.Walk(tmpDir, func(path string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, _ := filepath.Rel(tmpDir, path)
			if rel == "." {
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