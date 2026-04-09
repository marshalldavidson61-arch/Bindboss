// stub.go
// =============================================================================
// GRUG: This is the stub cave. When a user runs a bindboss-packed binary,
// THIS is the code that executes. It:
//   1. Locates its own payload (the appended tar.gz)
//   2. Optionally verifies the payload hash (if BINDBOSS_VERIFY is set)
//   3. Checks deps on first run (skips on subsequent runs via state file)
//   4. Runs pre_run hooks
//   5. Extracts the packed directory to a temp or persist location
//   6. Sets environment variables from config
//   7. Execs the run command with full stdin/stdout/stderr passthrough
//   8. Runs post_run hooks (exec_mode="fork" only — see note below)
//   9. Cleans up the tmpdir on exit (unless persist)
//  10. Exits with the child's exit code
//
// ACADEMIC: The exec model used here is NOT os/exec.Cmd.Run(). We use
// syscall.Exec (on Unix) which replaces the current process image entirely
// with the child. This means the child process IS the process — PID stays the
// same, signal handling is clean, and there's no wrapper overhead.
// On Windows, syscall.Exec is not available, so we fall back to cmd.Run()
// with manual signal forwarding via os/signal.
//
// exec_mode="fork" forces cmd.Run() on Unix too — useful when post_run hooks
// must fire, at the cost of a wrapper process. Default is "exec".
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
	"github.com/marshalldavidson61-arch/bindboss/internal/hooks"
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
	payloadInfo, err := archive.FindPayload(selfPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer payloadInfo.Reader.Close()

	// ------------------------------------------------------------------
	// STEP 2: Optional hash verification
	// GRUG: If BINDBOSS_VERIFY=1 is set, verify the payload hash before
	// extraction. This catches tampering or corruption before we exec anything.
	// Off by default — verification adds a full re-read of the payload.
	// ------------------------------------------------------------------
	if os.Getenv("BINDBOSS_VERIFY") == "1" {
		if !payloadInfo.HashPresent {
			fatalf("BINDBOSS_VERIFY=1 but binary %q has no stored hash (v1 format) — repack to enable verification", selfPath)
		}
		// GRUG: Close and reopen for verification — FindPayload consumed the reader.
		payloadInfo.Reader.Close()
		if err := archive.VerifyHash(selfPath); err != nil {
			fatalf("%v", err)
		}
		// Reopen for extraction
		payloadInfo, err = archive.FindPayload(selfPath)
		if err != nil {
			fatalf("%v", err)
		}
	}

	// ------------------------------------------------------------------
	// STEP 3: Determine extract directory
	// ------------------------------------------------------------------
	binaryName := filepath.Base(selfPath)

	extractDir, cleanup, err := resolveExtractDir(binaryName)
	if err != nil {
		fatalf("%v", err)
	}

	// ------------------------------------------------------------------
	// STEP 4: Extract payload (skip if persist dir already exists with content)
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
		if err := archive.Extract(payloadInfo.Reader, extractDir); err != nil {
			fatalf("%v", err)
		}
	}

	// ------------------------------------------------------------------
	// STEP 5: Load config from extracted directory
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
	// STEP 6: Dependency check (first run only)
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
	// STEP 7: Build environment
	// ------------------------------------------------------------------
	env := os.Environ()
	for _, kv := range cfg.Env {
		env = append(env, kv)
	}

	// ------------------------------------------------------------------
	// STEP 8: Run pre_run hooks
	// ------------------------------------------------------------------
	if len(cfg.Hooks.PreRun) > 0 {
		fmt.Fprintf(os.Stderr, "[bindboss] running pre_run hooks...\n")
		if err := hooks.Runner(cfg.Hooks.PreRun, extractDir, cfg.Name, env); err != nil {
			fatalf("%v", err)
		}
	}

	// ------------------------------------------------------------------
	// STEP 9: Parse and exec run command
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
	// STEP 10: Choose exec strategy based on exec_mode and platform
	// ------------------------------------------------------------------
	useFork := cfg.ExecMode == "fork" || runtime.GOOS == "windows"

	if !useFork {
		// GRUG: Unix exec path — replace this process with the child.
		// Clean and signal-safe. post_run hooks CANNOT fire after this.
		// The OS handles stdin/stdout/stderr inheritance automatically.
		if cleanup != nil {
			// GRUG: On Unix exec path, deferred cleanup won't run.
			// The tmpdir will be cleaned up by the OS on reboot, or
			// the user can run `bindboss reset <name>`.
			// If Cleanup=true and Persist=false, log a note.
			fmt.Fprintf(os.Stderr, "[bindboss] note: tmpdir %s will not be auto-cleaned (exec mode)\n", extractDir)
		}
		if err := syscall.Exec(cmdPath, argv, env); err != nil {
			fatalf("exec failed: %v", err)
		}
		// GRUG: Unreachable after syscall.Exec succeeds.
	}

	// Fork path: keep stub alive so post_run and cleanup can fire.
	exitCode := runWithSignalForwarding(cmdPath, argv, env, extractDir)

	// ------------------------------------------------------------------
	// STEP 11: post_run hooks (fork/Windows path only)
	// ------------------------------------------------------------------
	if len(cfg.Hooks.PostRun) > 0 {
		fmt.Fprintf(os.Stderr, "[bindboss] running post_run hooks...\n")
		if err := hooks.Runner(cfg.Hooks.PostRun, extractDir, cfg.Name, env); err != nil {
			// GRUG: post_run failure is logged but doesn't change the exit code.
			// The main command already finished — we can't un-run it.
			fmt.Fprintf(os.Stderr, "[bindboss] warning: post_run hook failed: %v\n", err)
		}
	}

	// ------------------------------------------------------------------
	// STEP 12: Cleanup (fork/Windows path only)
	// ------------------------------------------------------------------
	if cleanup != nil {
		cleanup()
	}

	os.Exit(exitCode)
}

// runWithSignalForwarding runs the child command with os/signal forwarding
// so Ctrl+C reaches the child instead of killing the wrapper.
// Returns the child's exit code.
func runWithSignalForwarding(cmdPath string, argv []string, env []string, workDir string) int {
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
			return exitErr.ExitCode()
		}
		fatalf("child process error: %v", err)
	}

	return 0
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