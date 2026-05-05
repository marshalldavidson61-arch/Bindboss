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
//   5. First run only: if install wizard config exists, run guided installer;
//      otherwise check deps, download missing ones via HTTP, wait for install
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
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/marshalldavidson61-arch/bindboss/internal/installer"
	"github.com/marshalldavidson61-arch/bindboss/internal/state"
	"github.com/marshalldavidson61-arch/bindboss/internal/updater"
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
	// STEP 3: Peek at config from archive to determine extract settings
	// GRUG: need to know persist mode before we decide where to extract.
	// chicken-and-egg: config is in the archive, but we need config to
	// know where to extract. solution: peek at bindboss.toml from the
	// tar.gz stream without extracting everything. fast and simple.
	// ------------------------------------------------------------------
	binaryName := filepath.Base(selfPath)

	peekCfg, err := peekConfigFromPayload(payloadInfo.Reader)
	if err != nil {
		fatalf("%v", err)
	}

	// GRUG: now we know persist mode. resolve the real extract directory.
	extractDir, cleanup, err := resolveExtractDir(binaryName, peekCfg)
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
		// GRUG: payloadInfo.Reader was consumed by peekConfigFromPayload.
		// reopen the payload for full extraction. same as BINDBOSS_VERIFY path.
		payloadInfo.Reader.Close()
		payloadInfo, err = archive.FindPayload(selfPath)
		if err != nil {
			fatalf("%v", err)
		}

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

	cfg, err = config.Validate(cfg)
	if err != nil {
		fatalf("%v", err)
	}

	// GRUG: if packer didn't set a name in toml, use the binary filename.
	// state file and logs use this name — should be human-readable.
	if cfg.Name == "" {
		cfg.Name = binaryName
	}

	// ------------------------------------------------------------------
	// STEP 5.5: Remote update check (if configured)
	// GRUG: if update URL is set in config, check GitHub for new commits.
	// if remote has new stuff, download zip and extract into persist dir.
	// this replaces old files with new ones. update = fresh install.
	// no update URL = skip entirely. binary stays as packed forever.
	// ------------------------------------------------------------------
	// GRUG: BINDBOSS_SKIP_UPDATE=1 = user wants to run whatever is already
	// on disk. useful offline, in CI, or when GitHub is having a bad day.
	// honored ONLY if we already have a cached copy — first-run still needs
	// to download the repo contents.
	skipUpdate := os.Getenv("BINDBOSS_SKIP_UPDATE") == "1"

	if cfg.Update.URL != "" && !skipUpdate {
		st, err := state.Load(cfg.Name)
		if err != nil {
			fatalf("%v", err)
		}

		result, err := updater.CheckAndDownload(
			cfg.Update.URL,
			cfg.Update.Branch,
			st.UpdateCommitSHA,
			st.UpdateCheckedAt,
			extractDir,
		)
		if err != nil {
			// GRUG: update check failed (network down, GitHub 503, rate limit, etc).
			// if we have a cached copy already, that's still runnable — warn and
			// continue with the old version. only FATAL on first run where we
			// have literally nothing to execute.
			if st.UpdateCommitSHA == "" {
				fatalf("first-run update failed and no cached copy exists: %v", err)
			}
			fmt.Fprintf(os.Stderr,
				"[bindboss] warning: update check failed (%v) — running cached version %s\n",
				err, updater.ShortSHA(st.UpdateCommitSHA))
			result = updater.Result{HasUpdate: false, CommitSHA: st.UpdateCommitSHA}
		}

		if result.HasUpdate {
			// GRUG: new version downloaded. verify it's a valid zip first.
			if err := updater.VerifyArchive(result.ArchivePath); err != nil {
				os.Remove(result.ArchivePath)
				fatalf("update archive verification failed: %v", err)
			}

			// GRUG: extract the new archive into the persist dir.
			// this replaces all old files with new ones from the repo.
			if err := updater.ExtractArchive(result.ArchivePath, extractDir); err != nil {
				os.Remove(result.ArchivePath)
				fatalf("update extraction failed: %v", err)
			}

			// GRUG: clean up the downloaded zip file. don't leave garbage around.
			if err := os.Remove(result.ArchivePath); err != nil {
				fmt.Fprintf(os.Stderr, "[bindboss] warning: could not remove update archive: %v\n", err)
			}

			// GRUG: reload config from the freshly extracted directory.
			// the update might have changed bindboss.toml. read it again.
			cfg, err = config.Load(extractDir)
			if err != nil {
				fatalf("%v", err)
			}
			cfg, err = config.Validate(cfg)
			if err != nil {
				fatalf("%v", err)
			}
			if cfg.Name == "" {
				cfg.Name = binaryName
			}

			// GRUG: force dep re-check after update. new version might have new deps.
			// nuke the dep state so the dep check runs again on this run.
			if err := state.Reset(cfg.Name); err != nil {
				fmt.Fprintf(os.Stderr, "[bindboss] warning: could not reset dep state after update: %v\n", err)
			}

			fmt.Fprintf(os.Stderr, "[bindboss] update complete: now at commit %s\n", updater.ShortSHA(result.CommitSHA))
		}

		// GRUG: save the commit SHA we saw (even if no update). throttling
		// and change detection both depend on this being current.
		if err := state.MarkUpdateChecked(cfg.Name, result.CommitSHA); err != nil {
			fmt.Fprintf(os.Stderr, "[bindboss] warning: could not save update state: %v\n", err)
		}
	}

	// ------------------------------------------------------------------
	// STEP 6: Dependency check / Install wizard (first run only)
	// GRUG: if install wizard config exists, run the guided installer.
	// if not, fall back to the old checker flow. backward compat = sacred.
	// ------------------------------------------------------------------
	hasNeeds := len(cfg.Needs) > 0
	hasInstall := cfg.Install.Enabled

	if hasNeeds || hasInstall {
		st, err := state.Load(cfg.Name)
		if err != nil {
			fatalf("%v", err)
		}

		if !st.Checked {
			if hasInstall {
				// GRUG: install wizard path. guided UI. downloads. the works.
				fmt.Fprintf(os.Stderr, "[bindboss] first run — launching install wizard...\n")
				if err := runInstallWizard(cfg, extractDir); err != nil {
					fatalf("%v", err)
				}
			} else {
				// GRUG: legacy path. no wizard. just check deps and open browser.
				fmt.Fprintf(os.Stderr, "[bindboss] first run — checking dependencies...\n")
				if err := checker.CheckAll(cfg); err != nil {
					fatalf("%v", err)
				}
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

// peekConfigFromPayload reads bindboss.toml from the tar.gz payload without
// fully extracting. Returns a Config with just enough info to determine
// extract settings (persist, dir). The reader is consumed after this call.
//
// GRUG: grug need to know persist mode before extracting. but config is in
// the archive. peek reads just bindboss.toml from the tar.gz. fast. simple.
// reader is dead after this — caller must reopen for full extraction.
func peekConfigFromPayload(r io.Reader) (config.Config, error) {
	data, err := archive.ReadFileFromTarGz(r, config.ConfigFileName)
	if err != nil {
		// GRUG: no bindboss.toml in archive = use defaults. not an error.
		// caller must provide --run at minimum, but extract settings are optional.
		return config.DefaultConfig(), nil
	}
	cfg, err := config.LoadFromBytes(data)
	if err != nil {
		return cfg, err
	}
	return cfg, nil
}

// resolveExtractDir determines where to extract the packed directory.
// Returns (dir, cleanupFn, error). cleanupFn is nil if no cleanup is needed.
//
// GRUG: two modes:
//   persist=false = fresh tmpdir every run. cleanup on exit.
//   persist=true  = fixed dir under ~/.bindboss/<name>/. survives across runs.
//                    no cleanup. faster for big runtimes. required for updates.
//
// GRUG: if cfg.Extract.Dir is set, use that as the persist location.
// this lets the user override where the extracted files live.
// useful for putting them on a fast disk or specific filesystem.
func resolveExtractDir(binaryName string, cfg config.Config) (string, func(), error) {
	if cfg.Extract.Persist {
		var persistDir string
		if cfg.Extract.Dir != "" {
			// GRUG: user-specified extract dir. use it directly.
			persistDir = cfg.Extract.Dir
		} else {
			// GRUG: default persist dir = ~/.bindboss/<name>/
			home, err := os.UserHomeDir()
			if err != nil {
				return "", nil, fmt.Errorf(
					"!!! FATAL: cannot find home directory for persist extract: %w", err)
			}
			persistDir = filepath.Join(home, ".bindboss", binaryName)
		}

		// GRUG: create persist dir if it doesn't exist. MkdirAll is idempotent.
		if err := os.MkdirAll(persistDir, 0755); err != nil {
			return "", nil, fmt.Errorf(
				"!!! FATAL: cannot create persist directory %q: %w", persistDir, err)
		}

		// GRUG: persist mode = no cleanup. files survive across runs.
		// this is the whole point of persist mode.
		return persistDir, nil, nil
	}

	// GRUG: non-persist mode = fresh tmpdir every run. cleanup on exit.
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

// runInstallWizard loads and executes the JSON install wizard.
// Reads install config from either inline TOML field or a file in extractDir.
//
// GRUG: two sources for the JSON config:
//   1. cfg.Install.ConfigInline — JSON embedded directly in bindboss.toml
//   2. cfg.Install.ConfigFile   — path to JSON file in the packed directory
// inline wins if both are set. neither set = FATAL.
//
// ---
// ACADEMIC: The install wizard is a finite state machine driven by a JSON
// configuration. It runs as a blocking call during the stub's first-run path.
// On success, the stub continues to the normal execution flow. On failure or
// user abort, the stub exits with a FATAL error and no state is persisted —
// the next run will re-trigger the wizard.
func runInstallWizard(cfg config.Config, extractDir string) error {
	var jsonData []byte

	if cfg.Install.ConfigInline != "" {
		// GRUG: inline JSON in TOML. just use it directly.
		jsonData = []byte(cfg.Install.ConfigInline)
	} else if cfg.Install.ConfigFile != "" {
		// GRUG: JSON file in packed directory. read it.
		path := filepath.Join(extractDir, cfg.Install.ConfigFile)
		var err error
		jsonData, err = os.ReadFile(path)
		if err != nil {
			return fmt.Errorf(
				"!!! FATAL: cannot read install config %q: %w\n"+
					"  Make sure the file exists in the packed directory.", path, err)
		}
	} else {
		// GRUG: install.enabled=true but no config provided. that is a config mistake.
		return fmt.Errorf(
			"!!! FATAL: install.enabled=true but no install_config or install_file provided\n" +
				"  Set install_config (inline JSON) or install_file (path) in bindboss.toml")
	}

	// GRUG: validate JSON is at least well-formed before handing to installer
	if !json.Valid(jsonData) {
		return fmt.Errorf("!!! FATAL: install config is not valid JSON")
	}

	installCfg, err := installer.Parse(jsonData)
	if err != nil {
		return err
	}

	runner := installer.NewRunner(installCfg)
	return runner.Run()
}

// fatalf prints a fatal error to stderr and exits 1. Never silent.
//
// GRUG: if the incoming message already starts with "!!! FATAL:" (because it
// came from a lower-level error that already formatted itself), strip the
// prefix so we don't print "!!! FATAL: !!! FATAL: ..." like a goofball.
func fatalf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	msg = strings.TrimPrefix(msg, "!!! FATAL: ")
	fmt.Fprintf(os.Stderr, "[bindboss] !!! FATAL: %s\n", msg)
	os.Exit(1)
}