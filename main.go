// main.go
// =============================================================================
// GRUG: This is the front door of the cave. Parses the subcommand and routes
// to the right handler. No framework, no magic — just a switch and a runner
// interface. Each subcommand owns its own flag.FlagSet so --help works per
// command without poisoning the global flag state.
//
// ACADEMIC: The subcommand dispatch pattern used here mirrors the Go standard
// library's own tool layout (go build, go test, etc.). Each command implements
// the Runner interface: Name() string, Run(args []string) error. The main
// function registers commands in a slice, finds the matching name, and calls
// Run with os.Args[2:]. Unrecognized subcommands print a help listing.
//
// Build tag absence (no "stub" tag) means this file compiles as the bindboss
// CLI tool. The stub/stub.go file uses `//go:build stub` so it's excluded here.
// =============================================================================

package main

import (
	"fmt"
	"os"

	"github.com/marshalldavidson61-arch/bindboss/cmd"
)

const version = "0.1.0"

const banner = `
  _     _           _ _
 | |__ (_)_ __   __| | |__   ___  ___ ___
 | '_ \| | '_ \ / _  | '_ \ / _ \/ __/ __|
 | |_) | | | | | (_| | |_) | (_) \__ \__ \
 |_.__/|_|_| |_|\__,_|_.__/ \___/|___/___/

 pack a directory. ship one binary. works anywhere.
 v` + version + "\n"

// Runner is implemented by every bindboss subcommand.
type Runner interface {
	Name() string
	Usage() string
	Run(args []string) error
}

func main() {
	commands := []Runner{
		cmd.NewPackCmd(),
		cmd.NewResetCmd(),
		cmd.NewInspectCmd(),
	}

	if len(os.Args) < 2 {
		printHelp(commands)
		os.Exit(0)
	}

	sub := os.Args[1]

	// GRUG: Handle global flags before subcommand dispatch.
	switch sub {
	case "-v", "--version", "version":
		fmt.Printf("bindboss %s\n", version)
		os.Exit(0)
	case "-h", "--help", "help":
		printHelp(commands)
		os.Exit(0)
	}

	for _, c := range commands {
		if c.Name() == sub {
			if err := c.Run(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "[bindboss] error: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}

	// GRUG: Unknown subcommand — print help and exit nonzero. Not silent.
	fmt.Fprintf(os.Stderr, "[bindboss] unknown command %q\n\n", sub)
	printHelp(commands)
	os.Exit(1)
}

func printHelp(commands []Runner) {
	fmt.Print(banner)
	fmt.Println("Usage:")
	fmt.Println("  bindboss <command> [arguments]")
	fmt.Println()
	fmt.Println("Commands:")
	for _, c := range commands {
		fmt.Printf("  %-12s\n", c.Name())
	}
	fmt.Println()
	fmt.Println("Run 'bindboss <command> --help' for command-specific usage.")
	fmt.Println()
	fmt.Println("Quick start:")
	fmt.Println("  bindboss pack ./myapp myapp --run=\"python main.py\"")
	fmt.Println("  bindboss pack ./grugbot grugbot --run=\"julia main.jl\" \\")
	fmt.Println("    --needs=\"julia,julia --version,https://julialang.org/downloads/\"")
	fmt.Println("  bindboss inspect ./grugbot")
	fmt.Println("  bindboss reset grugbot")
}