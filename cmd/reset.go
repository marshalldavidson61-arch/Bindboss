// reset.go
// =============================================================================
// GRUG: The reset command. Deletes the state file for a named binary so the
// next run treats it as a first run and re-checks dependencies.
// Useful after a fresh OS install, after updating a runtime, or just to verify
// the dep check still works.
// =============================================================================

package cmd

import (
	"flag"
	"fmt"

	"github.com/marshalldavidson61-arch/bindboss/internal/state"
)

type ResetCmd struct {
	fs *flag.FlagSet
}

func NewResetCmd() *ResetCmd {
	return &ResetCmd{fs: flag.NewFlagSet("reset", flag.ContinueOnError)}
}

func (c *ResetCmd) Name() string { return "reset" }
func (c *ResetCmd) Usage() string {
	return `reset <name>

  Reset the first-run state for a packed binary.
  The next time the binary runs it will re-check all dependencies.

  Example:
    bindboss reset grugbot
    bindboss reset myapp`
}

func (c *ResetCmd) Run(args []string) error {
	if err := c.fs.Parse(args); err != nil {
		return err
	}
	rest := c.fs.Args()
	if len(rest) < 1 {
		return fmt.Errorf("!!! FATAL: reset requires a binary name — usage: bindboss reset <name>")
	}

	name := rest[0]
	if err := state.Reset(name); err != nil {
		return err
	}

	fmt.Printf("[bindboss] ✓ state reset for %q — next run will re-check dependencies\n", name)
	return nil
}