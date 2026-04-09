// stub.go
// =============================================================================
// GRUG: This is the stub cave. THE most important file. When human double-clicks
// a bindboss-packed binary, THIS code runs. Not bindboss CLI. THIS.
//
// Grug stub do ten things in order:
//   1. Find own binary on disk (payload appended to end of THIS file)
//   2. If BINDBOSS_VERIFY=1, re-read entire payload and check SHA-256 hash
//   3. Make a temp dir and extract payload (tar.gz) into it
//   4. Read bindboss.toml from extracted dir
//   5. First run only: check deps, open browser if missing, wait for install
//   6. Write dep state so next run skips step 5
//   7. Set extra env vars from config
//   8. Run pre_run hooks
//   9. Exec the run command (syscall.Exec on Unix = replace self with child)
//  10. If exec_mode=fork: run post_run hooks and clean up tmpdir after child exits
//
// Step 9 is the key. syscall.Exec REPLACES this process. The child IS grug.
// No wrapper overhead. No zombie stub. Signal handling is clean.
// post_run hooks CANNOT fire in exec mode — grug is gone. Use fork mode if
// you need post_run.
//
// Build tag "stub" isolates this file. Only compiled as the standalone stub
// binary (go build -tags stub), not as part of the main bindboss CLI.
// The CLI packs THIS compiled binary as the output base, then appends payload.
//
// ---
// ACADEMIC: The stub's execution model has two paths depending on exec_mode:
//
//   exec (default, Unix only):
//     syscall.Exec(2) is invoked, which calls the execve(2) syscall directly.
//     This replaces the process image entirely — the stub's stack, heap, and
//     file descriptors are replaced by the child. The PID is preserved. stdin,
//     stdout, and stderr are inherited by the kernel without any pipe setup.
//     Signal disposition is reset to defaults by execve. post_run hooks
//     CANNOT fire because the stub process no longer exists after execve.
//
//   fork (explicit) or Windows (forced):
//     os/exec.Cmd.Start() + cmd.Wait() is used. The stub process remains alive
//     as a wrapper. Signals (SIGINT, SIGTERM) are forwarded to the child process
//     via os/signal + cmd.Process.Signal(). post_run hooks fire after cmd.Wait()
//     returns. tmpdir cleanup runs before os.Exit(childCode).
//
// Payload layout (v2 trailer, 121 bytes appended to stub ELF/PE/Mach-O):
//   [8 bytes  big-endian uint64  tar_offset  ]
//   [32 bytes SHA-256 of raw tar.gz bytes    ]
//   [64 bytes Ed25519 signature OR zeros     ]
//   [1 byte   flags: bit0=hash_present,      ]
//              bit1=sig_present              ]
//   [16 bytes magic: "BINDBOSS_PAYLOAD\x02"  ]
//
// v1 trailer (24 bytes, legacy) is detected by the "BINDBOSS_PAYLOAD\x01"
// magic suffix and read transparently — no hash/sig available in v1.
//
// HashDir canonical traversal (used by VerifyHash) uses sorted os.ReadDir
// with null-terminated path framing: for each file, SHA-256 absorbs
// len(relPath)||relPath||'\0'||fileBytes. This ensures hash stability
// across filesystems and OS-dependent directory enumeration order.
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
	// GRUG: find where grug lives on disk. payload is appended to THIS file.
	selfPath, err := os.Executable()
	if err != nil {
		fatalf("cannot locate own executable: %v", err)
	}
	// GRUG: resolve symlinks — payload is in the real binary, not the symlink.
	// os.Executable() may return a symlink path on some systems.
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		fatalf("cannot resolve symlink to own executable: %v", err)
	}

	// ------------------------------------------------------------------
	// STEP 1: Locate payload trailer
	// ------------------------------------------------------------------
	payloadInfo, err := archive.FindPayload(selfPath)
	if err != nil {
		fatalf("%v", err)
	}
	defer payloadInfo.Reader.Close()

	// ------------------------------------------------------------------
	// STEP 2: Optional hash verification
	// GRUG: BINDBOSS_VERIFY=1 = re-read whole payload and check SHA-256.
	// Catches corruption and tampering before grug runs anything.
	// Off by default — verification = full extra read of payload = slower.
	// ------------------------------------------------------------------
	if os.Getenv("BINDBOSS_VERIFY") == "1" {
		if !payloadInfo.HashPresent {
			fatalf("BINDBOSS_VERIFY=1 but binary %q has no stored hash (v1 format) — repack to enable verification", selfPath)
		}
		// GRUG: FindPayload already consumed the reader. close and reopen.
		payloadInfo.Reader.Close()
		if err := archive.VerifyHash(selfPath); err != nil {
			fatalf("%v", err)
		}
		// reopen for extraction below
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
	// STEP 4: Extract payload
	// GRUG: if persist dir already has content, skip re-extraction.
	// fresh tmpdir = always extract. persist dir with files = skip.
	// ------------------------------------------------------------------
	needsExtract := true
	if _, statErr := os.Stat(extractDir); statErr == nil {
		entries, _ := os.ReadDir(extractDir)
		if len(entries) > 0 {
			// GRUG: already extracted to persist dir. skip the work.
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

	// GRUG: if packer didn't set a name in toml, use the binary filename.
	// state file and logs use this name — should be human-readable.
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
				// GRUG: state write fail = not fatal. we just re-check next time.
				// annoying but correct. warn and continue.
				fmt.Fprintf(os.Stderr, "[bindboss] warning: could not save dep state: %v\n", err)
			}
		}
	}

	// ------------------------------------------------------------------
	// STEP 7: Build environment
	// ------------------------------------------------------------------
	env := os.Environ()
	for _, kv := range cfg.Env {
		// GRUG: append config env on top of process env. config wins on duplicates
		// because os.Environ() is read by the child in order, last write wins.
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
	// STEP 9: Parse run command and exec
	// ------------------------------------------------------------------
	parts := splitCmd(cfg.Run)
	if len(parts) == 0 {
		fatalf("run command is empty after parsing — check bindboss.toml 'run' field")
	}

	// GRUG: chdir to extract dir so relative paths in run command work.
	// "sh run.sh" only works if cwd = the dir that contains run.sh.
	if err := os.Chdir(extractDir); err != nil {
		fatalf("cannot chdir to extract dir %q: %v", extractDir, err)
	}

	// GRUG: resolve run command from PATH if it is not absolute.
	// "julia" needs to be found somewhere on PATH.
	cmdPath, err := exec.LookPath(parts[0])
	if err != nil {
		fatalf("run command %q not found on PATH: %v", parts[0], err)
	}

	argv := append([]string{cmdPath}, parts[1:]...)
	// GRUG: forward any extra args the user passed to us directly to the child.
	// "mypacked arg1 arg2" → child sees arg1 arg2.
	argv = append(argv, os.Args[1:]...)

	// ------------------------------------------------------------------
	// STEP 10: Choose exec strategy
	// ------------------------------------------------------------------
	// GRUG: fork mode = keep stub alive. needed for post_run and cleanup.
	// exec mode = replace self with child. clean, fast, no wrapper.
	// windows always forks — syscall.Exec not available on windows.
	useFork := cfg.ExecMode == "fork" || runtime.GOOS == "windows"

	if !useFork {
		// GRUG: Unix exec path. this process becomes the child.
		// nothing runs after this line if exec succeeds.
		// tmpdir cleanup will NOT run — OS cleans up on reboot or user runs reset.
		if cleanup != nil {
			fmt.Fprintf(os.Stderr, "[bindboss] note: tmpdir %s will not be auto-cleaned (exec mode)\n", extractDir)
		}
		if err := syscall.Exec(cmdPath, argv, env); err != nil {
			fatalf("exec failed: %v", err)
		}
		// GRUG: unreachable. syscall.Exec replaces this process on success.
	}

	// ------------------------------------------------------------------
	// Fork path: stub stays alive as wrapper
	// ------------------------------------------------------------------
	exitCode := runWithSignalForwarding(cmdPath, argv, env, extractDir)

	// ------------------------------------------------------------------
	// STEP 11: post_run hooks (fork / Windows path only)
	// GRUG: main command already finished. post_run failure = warn, not die.
	// we cannot un-run the main command. exit code is already set.
	// ------------------------------------------------------------------
	if len(cfg.Hooks.PostRun) > 0 {
		fmt.Fprintf(os.Stderr, "[bindboss] running post_run hooks...\n")
		if err := hooks.Runner(cfg.Hooks.PostRun, extractDir, cfg.Name, env); err != nil {
			fmt.Fprintf(os.Stderr, "[bindboss] warning: post_run hook failed: %v\n", err)
		}
	}

	// ------------------------------------------------------------------
	// STEP 12: Cleanup (fork / Windows path only)
	// ------------------------------------------------------------------
	if cleanup != nil {
		cleanup()
	}

	os.Exit(exitCode)
}

// runWithSignalForwarding runs the child command with signal forwarding so
// Ctrl+C (SIGINT) and SIGTERM reach the child instead of killing the wrapper.
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

	// GRUG: forward interrupt and terminate signals to child.
	// without this, Ctrl+C kills the wrapper but leaves the child running.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				cmd.Process.Signal(sig) //nolint:errcheck
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// GRUG: child exited nonzero. pass exit code through.
			return exitErr.ExitCode()
		}
		fatalf("child process error: %v", err)
	}

	return 0
}

// resolveExtractDir determines where to extract the packed directory.
// Returns (dir, cleanupFn, error). cleanupFn is nil if no cleanup is needed.
func resolveExtractDir(binaryName string) (string, func(), error) {
	// GRUG: always use fresh tmpdir for now. persist mode = future work.
	// tmpdir named after binary so `ls /tmp` is readable.
	dir, err := os.MkdirTemp("", "bindboss-"+binaryName+"-*")
	if err != nil {
		return "", nil, fmt.Errorf(
			"!!! FATAL: cannot create extract tmpdir: %w", err)
	}

	cleanup := func() {
		// GRUG: remove whole tmpdir on exit. not on exec path — stub is gone.
		os.RemoveAll(dir)
	}

	return dir, cleanup, nil
}

// splitCmd splits a shell-style command string into argv tokens.
// Handles single and double quoted strings. No shell expansion or escaping.
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