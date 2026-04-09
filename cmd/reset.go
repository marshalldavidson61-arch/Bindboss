// reset.go
// =============================================================================
// GRUG: The reset command. Grug reinstalled Julia. Grug want to prove
// dep check still works. Or grug moved to new machine and wants to confirm
// everything is installed. Delete the state file, next run does full
// dep check again from scratch. Simple. One command.
//
// `bindboss reset grugbot` deletes ~/.bindboss/grugbot.state.
// Next time grugbot runs, it is a "first run" again — checks all deps.
// Nothing else changes. Binary is untouched. Config is untouched.
//
// Not an error if state file does not exist. Idempotent.
// Reset a binary that has never run = no-op with success message.
//
// ---
// ACADEMIC: State persistence is documented in internal/state/state.go.
// Reset is the administrative escape hatch for the first-run cache.
//
// The state file records only two facts: Checked=true and CheckedAt=<unix>.
// There is no version field, no lock, and no transaction — the file is small
// enough that a read-check-delete sequence has no meaningful TOCTOU window.
// os.Remove is atomic on POSIX: either the file is gone or it is not, with
// no partial state. The ENOENT case is explicitly ignored — idempotency
// is the correct semantic for an administrative delete command.
//
// If the state directory (~/.bindboss/) itself is missing, reset is a no-op
// because statePath() creates the directory only during Save, not Load/Reset.
// This means `bindboss reset` on a clean machine silently succeeds, which
// is the correct behavior — there is nothing to reset.
// =============================================================================

package cmd

import (
	"flag"
	"fmt"

	"github.com/marshalldavidson61-arch/bindboss/internal/state"
)

// ResetCmd implements `bindboss reset`.
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
		// GRUG: no name = cannot know which state file to delete. fatal.
		return fmt.Errorf("!!! FATAL: reset requires a binary name — usage: bindboss reset <name>")
	}

	name := rest[0]
	if err := state.Reset(name); err != nil {
		return err
	}

	// GRUG: tell user it worked, even if file didn't exist. idempotent = success.
	fmt.Printf("[bindboss] ✓ state reset for %q — next run will re-check dependencies\n", name)
	return nil
}