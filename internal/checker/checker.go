// checker.go
// =============================================================================
// GRUG: This is the dep checker cave. Grug need Julia to run grug script.
// Julia not installed = sad. Bindboss fix: check if Julia here. Not here?
// Open browser, show install page, wait for human to install, check again.
// Loop until found or human gives up (Ctrl+C). No silent skip. No guessing.
//
// Check command = anything that exits 0 when tool present. "julia --version"
// works. "node --version" works. "which python3" works. Grug not care what
// the output is — only exit code matters. 0 = here. nonzero = not here.
//
// One missing dep = entire chain stops. Grug not half-install things.
// All deps must pass before stub continues to extraction and run.
//
// SplitCmd handles quoted args ("my tool" --flag) without invoking a shell.
// No shell = no injection. Grug not trust user input near shell eval.
//
// ---
// ACADEMIC: Dependency detection uses process exit codes as the ground truth
// oracle. A check command (e.g. "julia --version") exits 0 if the binary is
// found on PATH and functional; nonzero or exec-failure indicates absence.
// This is the POSIX convention followed by every well-behaved CLI tool.
//
// We do NOT parse version strings, inspect PATH manually, or stat filesystem
// locations — these are brittle and environment-dependent. Exit code is
// the only portable, tool-agnostic signal.
//
// Install flow is intentionally human-in-the-loop: we call xdg-open/open/start
// to surface the install URL in the system browser, print a prompt to stderr,
// then block on bufio.Scanner.Scan() (stdin read). After Enter is pressed we
// re-run IsPresent(). If still absent, we loop. The user retries as many times
// as needed or sends EOF (Ctrl+D) / SIGINT (Ctrl+C) to abort.
//
// SplitCmd implements a minimal shell tokenizer: bare tokens, single-quoted
// spans (no escape processing), and double-quoted spans (no escape processing).
// It is NOT a POSIX sh parser — it handles the common case of
// "command --flag value" and quoted paths. Shell metacharacters (&&, |, >,
// $VAR) are treated as literal text. Users who need shell semantics in a
// check command should wrap it: "sh -c 'your check here'".
// =============================================================================

package checker

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/marshalldavidson61-arch/bindboss/internal/config"
)

// CheckAll verifies every dep in cfg.Needs. For each missing dep it opens
// the install URL, waits for the user to confirm, and re-checks.
// Returns an error only if the user aborts (Ctrl+C / stdin closed) or if
// a check command itself is fatally malformed.
// Deps that are already present are skipped silently.
func CheckAll(cfg config.Config) error {
	for _, dep := range cfg.Needs {
		if err := checkOne(dep); err != nil {
			return err
		}
	}
	return nil
}

// checkOne checks a single dep. Loops until the dep is found or the user aborts.
func checkOne(dep config.Dep) error {
	if IsPresent(dep.Check) {
		// GRUG: already here. nothing to do. fast path.
		return nil
	}

	// GRUG: missing. tell human what is needed and where to get it.
	fmt.Fprintf(os.Stderr, "\n[bindboss] dependency missing: %s\n", dep.Name)
	if dep.Message != "" {
		// GRUG: custom message = extra context the packer wanted to show.
		fmt.Fprintf(os.Stderr, "[bindboss] %s\n", dep.Message)
	}
	fmt.Fprintf(os.Stderr, "[bindboss] install URL: %s\n", dep.URL)

	// GRUG: try to open browser. if it fails, URL is still printed above.
	// non-fatal — headless servers have no browser. human can copy the URL.
	if err := openBrowser(dep.URL); err != nil {
		fmt.Fprintf(os.Stderr, "[bindboss] (could not open browser automatically: %v)\n", err)
	}

	// GRUG: block until human says done. re-check after each Enter.
	// loop forever — human might need multiple tries (PATH not set, wrong version, etc.)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr,
			"[bindboss] press Enter after installing %s (Ctrl+C to abort)... ", dep.Name)

		if !scanner.Scan() {
			// GRUG: stdin closed = human hit Ctrl+D or pipe broke. not silent.
			return fmt.Errorf(
				"!!! FATAL: aborted waiting for %s install — stdin closed or interrupted",
				dep.Name)
		}

		if IsPresent(dep.Check) {
			fmt.Fprintf(os.Stderr, "[bindboss] %s found ✓\n", dep.Name)
			return nil
		}

		// GRUG: still not found. tell human which check failed so they know
		// whether it's a PATH issue or an install issue.
		fmt.Fprintf(os.Stderr,
			"[bindboss] %s still not found — check failed: %q\n"+
				"[bindboss] make sure the install completed and %s is on your PATH.\n",
			dep.Name, dep.Check, dep.Name)
	}
}

// IsPresent runs the check command and returns true if it exits 0.
// A check command that fails to exec (command not found) returns false —
// absence is the expected case here, not an error condition.
// Exported for testing.
func IsPresent(checkCmd string) bool {
	parts := SplitCmd(checkCmd)
	if len(parts) == 0 {
		// GRUG: empty check command = config mistake. treat as absent.
		return false
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	// GRUG: discard all output. only exit code matters.
	// version strings and error messages are noise to the checker.
	cmd.Stdout = nil
	cmd.Stderr = nil

	return cmd.Run() == nil
}

// openBrowser opens url in the system default browser.
// Uses xdg-open on Linux, open on macOS, start on Windows.
// Non-fatal — caller logs the error and continues.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/C", "start", url)
	default:
		return fmt.Errorf("unsupported OS %q for browser open", runtime.GOOS)
	}
	// GRUG: Start not Run. grug not wait for browser to close.
	// browser stays open after this function returns.
	return cmd.Start()
}

// SplitCmd splits a shell command string into argv without invoking a shell.
// Handles double-quoted and single-quoted spans and bare whitespace-delimited
// tokens. Does NOT process escape sequences or shell metacharacters.
// Exported for testing.
func SplitCmd(s string) []string {
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
			// GRUG: closing quote — end quoted span, do not include the quote char.
			inQuote = 0
		case inQuote == 0 && (ch == '"' || ch == '\''):
			// GRUG: opening quote — start quoted span, do not include the quote char.
			inQuote = ch
		case inQuote == 0 && ch == ' ':
			// GRUG: unquoted space = token boundary. flush current token.
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