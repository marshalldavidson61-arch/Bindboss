// hooks.go
// =============================================================================
// GRUG: grug want to run setup before main command. grug want cleanup after.
// hooks do that. put list of commands in bindboss.toml under [hooks].
// pre_run fires before main. post_run fires after.
// one hook fail = everything stop. no silent half-run. no skipping.
//
// GRUG: hooks are NOT shell. "sh -c '...'" if you need shell features.
// no pipes. no $() expansion. no &&. just argv. simple. safe.
//
// GRUG: two magic env vars injected into every hook:
//   BINDBOSS_EXTRACT_DIR  = where files were unpacked
//   BINDBOSS_BINARY_NAME  = name of the binary being run
//
// GRUG: post_run only fires on Windows or exec_mode=fork.
// on Unix with exec_mode=exec (default), syscall.Exec replaces this process.
// grug is gone. post_run cannot run. this is documented, not a bug.
//
// -----------------------------------------------------------------------------
// ACADEMIC FOOTER:
// The hook system follows a declarative sequential pipeline model. Each hook
// is an independent process invocation via exec.Command — not a shell eval.
// This eliminates shell injection as an attack surface at the cost of requiring
// explicit "sh -c" for shell features.
//
// Hooks share working directory (extractDir) and environment with the run
// command, plus two injected context variables. Execution is strictly ordered:
// hook[0] completes before hook[1] starts. First non-zero exit terminates the
// pipeline with a FATAL error — partial execution is worse than no execution.
//
// The post_run / exec_mode interaction is a fundamental consequence of
// syscall.Exec(2): it replaces the calling process image entirely. There is
// no return path and no deferred cleanup. The fork path (exec_mode="fork")
// uses os/exec.Cmd.Run() which keeps the stub alive, enabling post_run and
// cleanup at the cost of a wrapper process in the process tree.
// =============================================================================

package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner executes hookCmds in order. Stops on first failure — no silent skips.
// extractDir and binaryName are injected as env vars for each hook process.
// env is the base environment (os.Environ() + cfg.Env).
func Runner(hookCmds []string, extractDir, binaryName string, env []string) error {
	if len(hookCmds) == 0 {
		return nil
	}

	// GRUG: inject context so hooks know where they are and what binary called them
	hookEnv := append(env,
		"BINDBOSS_EXTRACT_DIR="+extractDir,
		"BINDBOSS_BINARY_NAME="+binaryName,
	)

	for i, raw := range hookCmds {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			// GRUG: empty string in hooks array = config mistake, not intentional no-op
			fmt.Fprintf(os.Stderr, "[bindboss] warning: hook[%d] is empty string — skipping\n", i)
			continue
		}

		parts := splitCmd(raw)
		if len(parts) == 0 {
			return fmt.Errorf("!!! FATAL: hook[%d] %q parsed to empty argv", i, raw)
		}

		cmdPath, err := exec.LookPath(parts[0])
		if err != nil {
			return fmt.Errorf(
				"!!! FATAL: hook[%d] command %q not found on PATH: %w", i, parts[0], err)
		}

		cmd := exec.Command(cmdPath, parts[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = hookEnv
		cmd.Dir = extractDir

		fmt.Fprintf(os.Stderr, "[bindboss] hook[%d]: %s\n", i, raw)

		if err := cmd.Run(); err != nil {
			return fmt.Errorf(
				"!!! FATAL: hook[%d] %q failed: %w\n"+
					"  (hooks run from %s)", i, raw, err, extractDir)
		}
	}

	return nil
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