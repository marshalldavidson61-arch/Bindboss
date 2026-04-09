// stub.go
// =============================================================================
// GRUG: This is the stub cave. When a user runs a bindboss-packed binary,
// THIS is the code that executes. It:
//   1. Locates its own payload (the appended tar.gz)
//   2. Checks deps on first run (skips on subsequent runs via state file)
//   3. Extracts the packed directory to a temp or persist location
//   4. Sets environment variables from config
//   5. Execs the run command with full stdin/stdout/stderr passthrough
//   6. Forwards signals so Ctrl+C reaches the child process
//   7. Cleans up the tmpdir on exit (unless --persist)
//   8. Exits with the child's exit code
//
// ACADEMIC: The exec model used here is NOT os/exec.Cmd.Run(). We use
// syscall.Exec (on Unix) which replaces the current process image entirely
// with the child. This means the child process IS the process — PID stays the
// same, signal handling is clean, and there's no wrapper overhead.
// On Windows, syscall.Exec is not available, so we fall back to cmd.Run()
// with manual signal forwarding via os/signal.
//
// The stub is compiled separately as part of the bindboss pack step and its
// binary is embedded into the bindboss packer via go:embed. When packing,
// the appropriate stub binary for the target platform is written as the output
// file base, then the payload is appended.
//
// Build tag "stub" ensures this file is only compiled as the standalone stub
// binary, not as part of the main bindboss CLI.
// =============================================================================

//go:build stub

package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/marshalldavidson61-arch/bindboss/internal/archive"
	"github.com/marshalldavidson61-arch/bindboss/internal/checker"
	"github.com/marshalldavidson61-arch/bindboss/internal/config"
	"github.com/marshalldavidson61-arch/bindboss/internal/state"
)

func main() {
	// GRUG: Find our own executable path. This is where the payload is appended.
	selfPath, err := os.Executable()
	if err != nil {
		fatalf("cannot locate own executable: %v", err)
	}
	// GRUG: Resolve symlinks — the payload is in the real binary, not the link.
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		fatalf("cannot resolve symlink to own executable: %v", err)
	}

	// ------------------------------------------------------------------
	// STEP 1: Find and validate the appended payload
	// ------------------------------------------------------------------
	payloadReader, err := archive.FindPayload(selfPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer payloadReader.Close()

	// ------------------------------------------------------------------
	// STEP 2: Determine extract directory
	// ------------------------------------------------------------------
	binaryName := filepath.Base(selfPath)

	extractDir, cleanup, err := resolveExtractDir(binaryName)
	if err != nil {
		fatalf("%v", err)
	}

	// ------------------------------------------------------------------
	// STEP 3: Extract payload (skip if persist dir already exists)
	// ------------------------------------------------------------------
	needsExtract := true
	if _, statErr := os.Stat(extractDir); statErr == nil {
		// GRUG: Directory exists. If we're in persist mode and it has content,
		// skip re-extraction. If it's empty or this is a fresh tmpdir, extract.
		entries, _ := os.ReadDir(extractDir)
		if len(entries) > 0 {
			needsExtract = false
		}
	}

	if needsExtract {
		if err := archive.Extract(payloadReader, extractDir); err != nil {
			fatalf("%v", err)
		}
	}

	// ------------------------------------------------------------------
	// STEP 4: Load config from extracted directory
	// ------------------------------------------------------------------
	cfg, err := config.Load(extractDir)
	if err != nil {
		fatalf("%v", err)
	}

	if err := config.Validate(cfg); err != nil {
		fatalf("%v", err)
	}

	// GRUG: Use binary filename as name if config doesn't provide one.
	if cfg.Name == "" {
		cfg.Name = binaryName
	}

	// ------------------------------------------------------------------
	// STEP 5: Dependency check (first run only)
	// ------------------------------------------------------------------
	if len(cfg.Needs) > 0 {
		st, err := state.Load(cfg.Name)
		if err != nil {
			fatalf("%v", err)
		}

		if !st.Checked {
			fmt.Fprintf(os.Stderr, "[bindboss] first run — checking dependencies...\n")
			if err := checker.CheckAll(cfg); err != nil {
				fatalf("%v", err)
			}
			if err := state.MarkChecked(cfg.Name); err != nil {
				// GRUG: Non-fatal — state write failure means we re-check next time,
				// which is annoying but not broken. Warn, don't die.
				fmt.Fprintf(os.Stderr, "[bindboss] warning: could not save dep state: %v\n", err)
			}
		}
	}

	// ------------------------------------------------------------------
	// STEP 6: Build environment
	// ------------------------------------------------------------------
	env := os.Environ()
	for _, kv := range cfg.Env {
		env = append(env, kv)
	}

	// ------------------------------------------------------------------
	// STEP 7: Parse and exec run command
	// ------------------------------------------------------------------
	parts := splitCmd(cfg.Run)
	if len(parts) == 0 {
		fatalf("run command is empty after parsing — check bindboss.toml 'run' field")
	}

	// GRUG: Change to the extracted directory before exec so relative paths
	// in the run command (e.g. "sh run.sh") resolve correctly.
	if err := os.Chdir(extractDir); err != nil {
		fatalf("cannot chdir to extract dir %q: %v", extractDir, err)
	}

	// GRUG: Resolve the command binary from PATH if it's not an absolute path.
	cmdPath, err := exec.LookPath(parts[0])
	if err != nil {
		fatalf("run command %q not found on PATH: %v", parts[0], err)
	}

	argv := append([]string{cmdPath}, parts[1:]...)
	// GRUG: Forward any extra args the user passed to us directly to the child.
	argv = append(argv, os.Args[1:]...)

	// ------------------------------------------------------------------
	// STEP 8: Cleanup registration (before exec replaces us on Unix)
	// ------------------------------------------------------------------
	// GRUG: On Unix, syscall.Exec replaces us — deferred cleanup won't run.
	// We handle cleanup here via a pre-exec signal handler only on Windows
	// where we use cmd.Run() instead of Exec.
	if cleanup != nil {
		defer cleanup()
	}

	// ------------------------------------------------------------------
	// STEP 9: Exec
	// ------------------------------------------------------------------
	if runtime.GOOS != "windows" {
		// GRUG: Unix path — replace this process with the child. Clean and signal-safe.
		// The OS handles stdin/stdout/stderr inheritance automatically.
		if err := syscall.Exec(cmdPath, argv, env); err != nil {
			fatalf("exec failed: %v", err)
		}
		// GRUG: Unreachable after syscall.Exec succeeds.
	} else {
		// GRUG: Windows path — no syscall.Exec, so use cmd.Run() with signal forwarding.
		runWithSignalForwarding(cmdPath, argv, env, extractDir)
	}
}

// runWithSignalForwarding runs the child command on Windows with os/signal
// forwarding so Ctrl+C reaches the child instead of killing the wrapper.
func runWithSignalForwarding(cmdPath string, argv []string, env []string, workDir string) {
	cmd := exec.Command(cmdPath, argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	cmd.Dir = workDir

	if err := cmd.Start(); err != nil {
		fatalf("failed to start child process: %v", err)
	}

	// GRUG: Forward interrupt signals to child process group.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				cmd.Process.Signal(sig)
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fatalf("child process error: %v", err)
	}
}

// resolveExtractDir determines where to extract the packed directory.
// Returns (dir, cleanupFn, error). cleanupFn is nil if no cleanup needed
// (persist mode) or if the OS handles it (Unix syscall.Exec replaces us).
func resolveExtractDir(binaryName string) (string, func(), error) {
	// GRUG: For now, always use a fresh tmpdir. Persist mode is a future flag
	// that will be read from the embedded config. This keeps the stub simple.
	// The extracted dir is named after the binary for easy identification.
	dir, err := os.MkdirTemp("", "bindboss-"+binaryName+"-*")
	if err != nil {
		return "", nil, fmt.Errorf(
			"!!! FATAL: cannot create extract tmpdir: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(dir)
	}

	return dir, cleanup, nil
}

// splitCmd splits a shell-style command string into argv tokens.
// Handles single and double quoted strings. No shell expansion.
func splitCmd(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var parts []string
	var current strings.Builder
	inQuote := rune(0)
	for _, ch := range s {
		switch {
		case inQuote != 0 && ch == inQuote:
			inQuote = 0
		case inQuote == 0 && (ch == '"' || ch == '\''):
			inQuote = ch
		case inQuote == 0 && ch == ' ':
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// fatalf prints a fatal error to stderr and exits 1. Never silent.
func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[bindboss] !!! FATAL: "+format+"\n", args...)
	os.Exit(1)
}