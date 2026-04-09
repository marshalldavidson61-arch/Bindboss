// checker.go
// =============================================================================
// GRUG: This is the dependency checker cave. Runs check commands, detects
// missing runtimes, opens install URLs, and waits for the user to finish
// installing before proceeding. Only runs on first launch — state.go
// remembers when the check has passed.
//
// ACADEMIC: Dependency detection uses process exit codes as the oracle.
// A check command (e.g. "julia --version") exits 0 if the tool is present
// and nonzero (or fails to exec) if it is absent. This is the POSIX convention
// and works for every runtime that follows it. We do NOT parse version strings
// or check PATH manually — exit code is the ground truth.
//
// The install flow is intentionally human-in-the-loop: we open the download
// URL in the system browser (xdg-open / open / start), print a message, and
// block on a keystroke. After the user presses Enter we re-run the check.
// If it still fails we loop — the user can retry as many times as needed,
// or Ctrl+C to abort. No silent timeouts, no auto-installs without consent.
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

// checkOne checks a single dep. Loops until found or user aborts.
func checkOne(dep config.Dep) error {
	if IsPresent(dep.Check) {
		// GRUG: Already installed. Nothing to do.
		return nil
	}

	// GRUG: Missing. Tell the user and open the URL.
	fmt.Fprintf(os.Stderr, "\n[bindboss] dependency missing: %s\n", dep.Name)
	if dep.Message != "" {
		fmt.Fprintf(os.Stderr, "[bindboss] %s\n", dep.Message)
	}
	fmt.Fprintf(os.Stderr, "[bindboss] install URL: %s\n", dep.URL)

	// GRUG: Attempt to open the URL in the system browser.
	// Non-fatal if this fails — the URL is printed above regardless.
	if err := openBrowser(dep.URL); err != nil {
		fmt.Fprintf(os.Stderr, "[bindboss] (could not open browser automatically: %v)\n", err)
	}

	// GRUG: Loop: wait for user to press Enter, re-check, repeat until found.
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr,
			"[bindboss] press Enter after installing %s (Ctrl+C to abort)... ", dep.Name)

		if !scanner.Scan() {
			// GRUG: stdin closed or Ctrl+C. Not a silent failure.
			return fmt.Errorf(
				"!!! FATAL: aborted waiting for %s install — stdin closed or interrupted",
				dep.Name)
		}

		if IsPresent(dep.Check) {
			fmt.Fprintf(os.Stderr, "[bindboss] %s found ✓\n", dep.Name)
			return nil
		}

		fmt.Fprintf(os.Stderr,
			"[bindboss] %s still not found — check failed: %q\n"+
				"[bindboss] make sure the install completed and %s is on your PATH.\n",
			dep.Name, dep.Check, dep.Name)
	}
}

// IsPresent runs the check command and returns true if it exits 0.
// A check command that fails to exec (e.g. command not found) returns false,
// not an error — absence is the expected case here.
// Exported for testing.
func IsPresent(checkCmd string) bool {
	parts := SplitCmd(checkCmd)
	if len(parts) == 0 {
		return false
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	// GRUG: Discard stdout/stderr from the check command — we only care
	// about exit code. Version strings and error output are noise here.
	cmd.Stdout = nil
	cmd.Stderr = nil

	err := cmd.Run()
	return err == nil
}

// openBrowser opens url in the system default browser.
// Uses xdg-open on Linux, open on macOS, start on Windows.
// Returns an error if the open command itself fails, which is non-fatal.
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
	return cmd.Start() // GRUG: Start not Run — don't wait for the browser to close.
}

// SplitCmd splits a shell command string into argv without invoking a shell.
// Handles quoted strings ("julia --version", 'hello world') and bare tokens.
// This is not a full POSIX parser — it handles the common cases for check
// commands. If someone passes a check command with shell redirections (&&, |)
// they should wrap it in a script.
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
			// GRUG: Closing quote — end quoted span.
			inQuote = 0
		case inQuote == 0 && (ch == '"' || ch == '\''):
			// GRUG: Opening quote — start quoted span.
			inQuote = ch
		case inQuote == 0 && ch == ' ':
			// GRUG: Unquoted space = token boundary.
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