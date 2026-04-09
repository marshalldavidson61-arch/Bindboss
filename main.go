// main.go
// =============================================================================
// GRUG: Entry point. Dispatches subcommands. No framework. Just a slice of
// runners and a switch. Adding a new command = implement Runner, append it.
//
// ACADEMIC: The Runner interface is the only abstraction. Each subcommand
// owns its flag set and arg parsing. main() does nothing except route.
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
		printUsage(runners)
		os.Exit(1)
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	for _, r := range runners {
		if r.Name() == subcmd {
			if err := r.Run(args); err != nil {
				fmt.Fprintf(os.Stderr, "[bindboss] %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	fmt.Fprintf(os.Stderr, "[bindboss] unknown command %q\n\n", subcmd)
	printUsage(runners)
	os.Exit(1)
}

func printUsage(runners []Runner) {
	fmt.Fprintf(os.Stderr, "bindboss — pack any directory into a self-extracting executable\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n  bindboss <command> [args]\n\nCommands:\n")
	for _, r := range runners {
		fmt.Fprintf(os.Stderr, "  %-10s %s\n", r.Name(), firstLine(r.Usage()))
	}
	fmt.Fprintf(os.Stderr, "\nRun `bindboss <command>` with no args for command help.\n")
}

// firstLine returns the first non-empty line of a usage string.
func firstLine(s string) string {
	for _, line := range splitLines(s) {
		if line != "" {
			return line
		}
	}
	return s
}

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