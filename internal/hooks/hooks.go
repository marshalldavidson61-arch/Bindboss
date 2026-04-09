// hooks.go
// =============================================================================
// GRUG: This is the hooks cave. Runs pre/post commands before and after the
// main run command. Hooks are declared in bindboss.toml — no embedded VM,
// no Lua, no scripts that need a runtime. Just a list of shell commands that
// run in order. If one fails, we stop. No silent failures.
//
// ACADEMIC: The hook system follows a declarative pipeline model. Each hook
// is an independent process invocation. Hooks share the same working directory
// and environment as the run command, plus two injected variables:
//
//   BINDBOSS_EXTRACT_DIR  — absolute path to the extracted payload directory
//   BINDBOSS_BINARY_NAME  — basename of the packed binary being run
//
// Hooks are NOT run through a shell (no $(...) expansion, no pipes). If you
// need shell features, hook command should be: "sh -c 'your shell stuff here'".
// This is intentional: shell expansion in hooks is a security surface.
//
// Hook execution order:
//   1. pre_run hooks  — run before dep check and before the main command
//   2. (main run command executes)
//   3. post_run hooks — run after the main command exits (Windows only;
//      on Unix syscall.Exec replaces us so post_run cannot fire)
//
// GRUG NOTE on post_run: On Unix we use syscall.Exec which replaces this
// process entirely. post_run hooks physically cannot run after that. They
// are only meaningful on Windows (cmd.Run path) or if you set exec_mode="fork"
// in bindboss.toml. Document this clearly so users aren't surprised.
// =============================================================================

package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Runner executes a list of hook commands in order, stopping on first failure.
// extractDir and binaryName are injected as env vars for each hook process.
// env is the base environment (usually os.Environ() + cfg.Env).
//
// Returns a non-nil error if any hook exits non-zero or cannot be started.
// Never silently skips a hook failure.
func Runner(hookCmds []string, extractDir, binaryName string, env []string) error {
	if len(hookCmds) == 0 {
		return nil
	}

	// GRUG: Inject bindboss context into the hook environment.
	hookEnv := append(env,
		"BINDBOSS_EXTRACT_DIR="+extractDir,
		"BINDBOSS_BINARY_NAME="+binaryName,
	)

	for i, raw := range hookCmds {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			// GRUG: Empty hook strings are a config mistake, not intentional no-ops.
			// Warn but don't fatal — the user may have trailing commas in their toml array.
			fmt.Fprintf(os.Stderr, "[bindboss] warning: hook[%d] is empty string — skipping\n", i)
			continue
		}

		parts := splitCmd(raw)
		if len(parts) == 0 {
			return fmt.Errorf("!!! FATAL: hook[%d] %q parsed to empty argv", i, raw)
		}

		// GRUG: Resolve the hook binary from PATH.
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
// Exported so tests and the stub can share the same implementation.
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