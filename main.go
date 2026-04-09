// main.go
// =============================================================================
// GRUG: Entry point. Grug dispatch subcommand. That is all grug do here.
// No business logic. No parsing. No config. Just: "which command?" → go there.
//
// Commands:
//   pack     — pack a directory into a self-extracting binary
//   inspect  — print what is inside a packed binary
//   verify   — check hash + optional Ed25519 signature
//   keygen   — generate an Ed25519 keypair for signing
//   reset    — delete first-run state so dep check runs again
//
// Adding a new command = implement Runner interface, append to runners slice.
// That is the whole extension model. No plugin system. No reflection. Just
// a slice and a loop.
//
// Error from any command = print to stderr, exit 1. Always. No silent exits.
//
// ---
// ACADEMIC: The Runner interface is the only dispatch abstraction in bindboss.
// Each subcommand owns its own flag.FlagSet and argument parsing — this is
// the standard Go subcommand pattern (as used by `go`, `kubectl`, `docker`).
// main() is a pure router: O(n) linear scan over a small fixed slice.
//
// The separation of concerns is strict:
//   main.go      — routing only, no logic
//   cmd/*.go     — CLI flag parsing, user-facing I/O, orchestration
//   internal/*   — all business logic, no os.Exit, no flag parsing
//   pkg/*        — library API, thin wrapper over internal, no os.Exit
//   stub/stub.go — standalone binary, compiled separately with build tag
//
// This layering ensures that internal packages are testable in isolation
// without any flag state or process lifecycle side effects.
// =============================================================================

package main

import (
	"fmt"
	"os"

	"github.com/marshalldavidson61-arch/bindboss/cmd"
)

// Runner is implemented by every bindboss subcommand.
type Runner interface {
	Name() string
	Usage() string
	Run(args []string) error
}

func main() {
	runners := []Runner{
		cmd.NewPackCmd(),
		cmd.NewInspectCmd(),
		cmd.NewResetCmd(),
		cmd.NewVerifyCmd(),
		cmd.NewKeygenCmd(),
	}

	if len(os.Args) < 2 {
		// GRUG: no subcommand = print help and exit. not a panic. not a crash.
		printUsage(runners)
		os.Exit(1)
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	for _, r := range runners {
		if r.Name() == subcmd {
			if err := r.Run(args); err != nil {
				// GRUG: command failed = print error, exit 1. always. no silent exits.
				fmt.Fprintf(os.Stderr, "[bindboss] %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// GRUG: unknown command = tell user exactly what they typed, then show help.
	fmt.Fprintf(os.Stderr, "[bindboss] unknown command %q\n\n", subcmd)
	printUsage(runners)
	os.Exit(1)
}

// printUsage prints the top-level help listing all available commands.
func printUsage(runners []Runner) {
	fmt.Fprintf(os.Stderr, "bindboss — pack any directory into a self-extracting executable\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n  bindboss <command> [args]\n\nCommands:\n")
	for _, r := range runners {
		fmt.Fprintf(os.Stderr, "  %-10s %s\n", r.Name(), firstLine(r.Usage()))
	}
	fmt.Fprintf(os.Stderr, "\nRun `bindboss <command>` with no args for command help.\n")
}

// firstLine returns the first non-empty line of a usage string.
// Used to show a one-liner summary next to each command name.
func firstLine(s string) string {
	for _, line := range splitLines(s) {
		if line != "" {
			return line
		}
	}
	return s
}

// splitLines splits a string on newlines without using strings.Split
// (avoids an import just for this tiny helper).
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, ch := range s {
		if ch == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}