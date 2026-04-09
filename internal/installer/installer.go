// installer.go
// =============================================================================
// GRUG: This is the install wizard cave. JSON in, pretty terminal UI out.
// Define your installer in JSON — title, steps, deps, downloads — and grug
// renders a guided install experience. Like an MSI wizard but in the terminal.
//
// Steps grug understands:
//   welcome   — show a greeting message, wait for Enter
//   license   — show license text, user must type "accept" to proceed
//   deps      — check all dependencies, download missing ones, verify install
//   message   — show informational text, wait for Enter
//   finish    — show completion message, exit
//
// Navigation:
//   Enter          = next step
//   "back" + Enter = go back one step (where applicable)
//   Ctrl+C         = abort install entirely (FATAL exit)
//
// GRUG: no ncurses. no termbox. no third-party TUI library. just fmt and
// box-drawing characters. works on every terminal. zero dependencies.
//
// GRUG: every step prints a header showing where you are: "Step 2/5 — License"
// so human never feels lost. progress is always visible.
//
// ---
// ACADEMIC: The installer follows a finite state machine model where each step
// is a node and transitions are triggered by user input. The step list is
// defined declaratively in JSON, parsed at startup, and executed sequentially.
//
// The JSON schema uses a discriminated union pattern: each step object has a
// "type" field that determines which additional fields are relevant. Unknown
// types are rejected at parse time (fail-fast) rather than at execution time
// to prevent mid-install failures.
//
// Terminal UI rendering uses Unicode box-drawing characters (U+2550 et al.)
// for visual structure. No ANSI escape codes for cursor movement — output is
// append-only, which means the install log is readable if piped to a file.
// This is a deliberate trade-off: we sacrifice "fancy" re-rendering for
// universal compatibility and debuggability.
//
// The download-and-install flow for each dependency is:
//   1. checker.IsPresent(dep.Check) — fast path if already installed
//   2. download.Download(dep.DownloadURL) — fetch installer via HTTP
//   3. download.LaunchInstaller(path) — run the downloaded file
//   4. User presses Enter when done
//   5. checker.IsPresent(dep.Check) — verify installation succeeded
//   6. Loop back to step 3 if still missing (user may retry)
//
// State is NOT written during the install wizard. State persistence (marking
// deps as checked) happens in the stub AFTER the wizard completes successfully.
// This ensures a crashed/aborted wizard leaves no partial state.
// =============================================================================

package installer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/marshalldavidson61-arch/bindboss/internal/checker"
	"github.com/marshalldavidson61-arch/bindboss/internal/download"
)

// =============================================================================
// JSON Schema Types
// =============================================================================

// InstallConfig is the top-level JSON structure for the install wizard.
type InstallConfig struct {
	Title   string `json:"title"`   // shown in the header bar
	Version string `json:"version"` // shown next to title
	Steps   []Step `json:"steps"`   // ordered list of wizard steps
}

// Step is one screen in the install wizard. Type determines behavior.
// Only fields relevant to the step type need to be populated.
type Step struct {
	Type    string   `json:"type"`    // welcome, license, deps, message, finish
	Title   string   `json:"title"`   // step heading shown in the UI
	Content string   `json:"content"` // text body (welcome message, license, info)
	Deps    []DepDef `json:"deps"`    // only for type=deps
}

// DepDef is one downloadable dependency in a deps step.
// Extends the base config.Dep with download-specific fields.
type DepDef struct {
	Name        string `json:"name"`         // human-readable name, e.g. "Julia 1.9+"
	Check       string `json:"check"`        // command to test presence, e.g. "julia --version"
	DownloadURL string `json:"download_url"` // direct download link for installer
	FileName    string `json:"file_name"`    // override downloaded filename (optional)
	Hash        string `json:"hash"`         // expected SHA-256 hex (optional)
	Message     string `json:"message"`      // extra context shown to user (optional)
	FallbackURL string `json:"fallback_url"` // browser URL if download fails (optional)
}

// =============================================================================
// Parser
// =============================================================================

// Parse reads an InstallConfig from JSON bytes. Validates all step types
// at parse time — unknown type = FATAL. No mid-install surprises.
func Parse(data []byte) (*InstallConfig, error) {
	var cfg InstallConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot parse install.json: %w", err)
	}

	if len(cfg.Steps) == 0 {
		return nil, fmt.Errorf("!!! FATAL: install.json has no steps — nothing to install")
	}

	// GRUG: validate every step type upfront. catch config mistakes early.
	validTypes := map[string]bool{
		"welcome": true, "license": true, "deps": true,
		"message": true, "finish": true,
	}
	for i, step := range cfg.Steps {
		if !validTypes[step.Type] {
			return nil, fmt.Errorf(
				"!!! FATAL: install.json step[%d] has unknown type %q — "+
					"valid types: welcome, license, deps, message, finish", i, step.Type)
		}
		if step.Type == "deps" && len(step.Deps) == 0 {
			return nil, fmt.Errorf(
				"!!! FATAL: install.json step[%d] is type \"deps\" but has no deps listed", i)
		}
		if step.Type == "license" && strings.TrimSpace(step.Content) == "" {
			return nil, fmt.Errorf(
				"!!! FATAL: install.json step[%d] is type \"license\" but has no content", i)
		}
		// GRUG: validate dep definitions in deps steps
		if step.Type == "deps" {
			for j, dep := range step.Deps {
				if dep.Name == "" {
					return nil, fmt.Errorf(
						"!!! FATAL: install.json step[%d].deps[%d] has empty name", i, j)
				}
				if dep.Check == "" {
					return nil, fmt.Errorf(
						"!!! FATAL: install.json step[%d].deps[%d] (%s) has empty check command", i, j, dep.Name)
				}
				if dep.DownloadURL == "" && dep.FallbackURL == "" {
					return nil, fmt.Errorf(
						"!!! FATAL: install.json step[%d].deps[%d] (%s) has no download_url or fallback_url", i, j, dep.Name)
				}
			}
		}
	}

	return &cfg, nil
}

// ParseFile reads install.json from disk. Convenience wrapper around Parse.
func ParseFile(path string) (*InstallConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot read install config %q: %w", path, err)
	}
	return Parse(data)
}

// =============================================================================
// Runner — executes the install wizard
// =============================================================================

// Runner holds the state for an active install wizard session.
type Runner struct {
	config  *InstallConfig
	scanner *bufio.Scanner
	writer  io.Writer // where UI output goes (os.Stderr by default)
}

// NewRunner creates a wizard runner. Output goes to stderr (not stdout)
// so the wizard UI doesn't pollute program output.
func NewRunner(cfg *InstallConfig) *Runner {
	return &Runner{
		config:  cfg,
		scanner: bufio.NewScanner(os.Stdin),
		writer:  os.Stderr,
	}
}

// NewRunnerWithIO creates a runner with custom I/O — used for testing.
func NewRunnerWithIO(cfg *InstallConfig, reader io.Reader, writer io.Writer) *Runner {
	return &Runner{
		config:  cfg,
		scanner: bufio.NewScanner(reader),
		writer:  writer,
	}
}

// Run executes every step in order. Returns nil on successful completion.
// Returns an error if the user aborts or a critical step fails.
//
// GRUG: this is the main loop. one step at a time. no skipping. no jumping.
// abort = FATAL. finish = success. that's it.
func (r *Runner) Run() error {
	totalSteps := len(r.config.Steps)

	r.printBanner()

	for i := 0; i < totalSteps; i++ {
		step := r.config.Steps[i]

		r.printStepHeader(i+1, totalSteps, step.Title)

		var err error
		var goBack bool

		switch step.Type {
		case "welcome":
			goBack, err = r.runWelcome(step)
		case "license":
			goBack, err = r.runLicense(step)
		case "deps":
			goBack, err = r.runDeps(step)
		case "message":
			goBack, err = r.runMessage(step)
		case "finish":
			err = r.runFinish(step)
			// GRUG: no going back from finish. you're done.
		default:
			// GRUG: should never reach here — Parse validated all types.
			err = fmt.Errorf("!!! FATAL: unknown step type %q", step.Type)
		}

		if err != nil {
			return err
		}

		if goBack && i > 0 {
			i -= 2 // -2 because loop does i++ → net effect: go back one step
		} else if goBack && i == 0 {
			i = -1 // GRUG: already at first step. loop does i++ → stays at 0
		}
	}

	return nil
}

// =============================================================================
// Step Renderers
// =============================================================================

// runWelcome shows a welcome message and waits for Enter or "back".
func (r *Runner) runWelcome(step Step) (goBack bool, err error) {
	if step.Content != "" {
		r.writeln("")
		r.writeln(step.Content)
	}
	r.writeln("")
	return r.promptNextBack("Press Enter to continue...")
}

// runLicense shows license text and requires the user to type "accept".
// GRUG: no checkbox. no "I have read the terms". type the word. prove it.
func (r *Runner) runLicense(step Step) (goBack bool, err error) {
	r.writeln("")
	// GRUG: print license in a box so it stands out from the UI chrome
	r.writeln("┌─── License Agreement ───────────────────────────────────┐")
	for _, line := range strings.Split(step.Content, "\n") {
		r.writef("│ %s\n", line)
	}
	r.writeln("└────────────────────────────────────────────────────────┘")
	r.writeln("")

	for {
		r.write("  Type \"accept\" to agree, \"back\" to go back, or Ctrl+C to abort: ")
		input, err := r.readLine()
		if err != nil {
			return false, err
		}

		input = strings.ToLower(strings.TrimSpace(input))
		switch input {
		case "accept":
			r.writeln("  ✓ License accepted.")
			return false, nil
		case "back":
			return true, nil
		default:
			r.writeln("  ✗ Please type \"accept\" to continue.")
		}
	}
}

// runDeps checks each dependency and downloads/installs missing ones.
// This is the workhorse step — it's where the download cave gets called.
func (r *Runner) runDeps(step Step) (goBack bool, err error) {
	r.writeln("")

	allFound := true
	for i, dep := range step.Deps {
		r.writef("  [%d/%d] Checking %s...", i+1, len(step.Deps), dep.Name)

		if checker.IsPresent(dep.Check) {
			r.writeln(" ✓ found")
			continue
		}

		r.writeln(" ✗ not found")
		allFound = false

		if dep.Message != "" {
			r.writef("         %s\n", dep.Message)
		}

		// GRUG: download and install loop. keeps going until dep is found or user aborts.
		installed, depErr := r.installDep(dep)
		if depErr != nil {
			return false, depErr
		}
		if !installed {
			// GRUG: user chose to go back from dep install
			return true, nil
		}
	}

	if allFound {
		r.writeln("")
		r.writeln("  ✓ All dependencies satisfied!")
	}

	r.writeln("")
	return r.promptNextBack("Press Enter to continue...")
}

// installDep handles the download → install → verify loop for a single dep.
// Returns (true, nil) when dep is verified installed.
// Returns (false, nil) if user chose to go back.
// Returns (false, error) on fatal errors.
func (r *Runner) installDep(dep DepDef) (installed bool, err error) {
	for attempts := 0; ; attempts++ {
		r.writeln("")

		if dep.DownloadURL != "" {
			r.writef("  Downloading %s...\n", dep.Name)

			// GRUG: show a simple text progress bar
			dlResult, dlErr := download.Download(download.Options{
				URL:          dep.DownloadURL,
				FileName:     dep.FileName,
				ExpectedHash: dep.Hash,
				OnProgress: func(downloaded, total int64) {
					if total > 0 {
						pct := float64(downloaded) / float64(total) * 100
						bar := progressBar(pct, 30)
						r.writef("\r  %s %.0f%% (%d/%d bytes)", bar, pct, downloaded, total)
					} else {
						r.writef("\r  Downloaded %d bytes...", downloaded)
					}
				},
			})

			if dlErr != nil {
				r.writef("\n  ✗ Download failed: %v\n", dlErr)
				if dep.FallbackURL != "" {
					r.writef("  Fallback: please download manually from:\n    %s\n", dep.FallbackURL)
				}
			} else {
				r.writeln("") // newline after progress bar
				r.writef("  ✓ Downloaded to: %s\n", dlResult.FilePath)

				// Launch installer
				r.writef("  Launching %s installer...\n", dep.Name)
				_, launchErr := download.LaunchInstaller(dlResult.FilePath)
				if launchErr != nil {
					r.writef("  ✗ Could not launch installer: %v\n", launchErr)
					r.writef("  Please run the installer manually: %s\n", dlResult.FilePath)
				}
			}
		} else if dep.FallbackURL != "" {
			r.writef("  No direct download available. Please install %s from:\n", dep.Name)
			r.writef("    %s\n", dep.FallbackURL)
		}

		// GRUG: wait for user to finish installing, then re-check
		r.writeln("")
		r.write("  Press Enter after installing (or type \"back\" to go back, \"retry\" to re-download): ")
		input, readErr := r.readLine()
		if readErr != nil {
			return false, readErr
		}

		input = strings.ToLower(strings.TrimSpace(input))
		if input == "back" {
			return false, nil
		}
		if input == "retry" {
			continue
		}

		// Re-check
		r.writef("  Verifying %s...", dep.Name)
		if checker.IsPresent(dep.Check) {
			r.writeln(" ✓ found!")
			return true, nil
		}

		r.writeln(" ✗ still not found")
		r.writef("  Check that %s is installed and available on your PATH.\n", dep.Name)
		r.writef("  Check command: %s\n", dep.Check)

		if attempts >= 2 {
			r.writeln("")
			r.writeln("  ⚠ Multiple attempts failed. Common issues:")
			r.writeln("    • The installer completed but the terminal needs to be restarted")
			r.writeln("    • The binary is not on your PATH")
			r.writeln("    • The wrong version was installed")
		}

		// GRUG: loop — user gets to try again
	}
}

// runMessage shows informational text and waits for Enter.
func (r *Runner) runMessage(step Step) (goBack bool, err error) {
	if step.Content != "" {
		r.writeln("")
		r.writeln(step.Content)
	}
	r.writeln("")
	return r.promptNextBack("Press Enter to continue...")
}

// runFinish shows the completion message. No going back from here.
func (r *Runner) runFinish(step Step) error {
	r.writeln("")
	if step.Content != "" {
		r.writeln(step.Content)
	} else {
		r.writeln("  Installation complete! 🎉")
	}
	r.writeln("")
	r.printFooter()
	return nil
}

// =============================================================================
// UI Helpers
// =============================================================================

// printBanner prints the top-level wizard header.
func (r *Runner) printBanner() {
	title := r.config.Title
	if title == "" {
		title = "bindboss installer"
	}
	if r.config.Version != "" {
		title += " v" + r.config.Version
	}

	width := 60
	r.writeln("")
	r.writeln("╔" + strings.Repeat("═", width) + "╗")
	r.writef("║  %-*s║\n", width-2, title)
	r.writeln("╚" + strings.Repeat("═", width) + "╝")
}

// printStepHeader prints the step indicator line.
func (r *Runner) printStepHeader(current, total int, title string) {
	r.writeln("")
	r.writeln("────────────────────────────────────────────────────────────────")
	if title != "" {
		r.writef("  Step %d/%d — %s\n", current, total, title)
	} else {
		r.writef("  Step %d/%d\n", current, total)
	}
	r.writeln("────────────────────────────────────────────────────────────────")
}

// printFooter prints the closing line.
func (r *Runner) printFooter() {
	r.writeln("════════════════════════════════════════════════════════════════")
}

// promptNextBack shows a prompt and returns goBack=true if user typed "back".
// Returns an error if stdin is closed (Ctrl+D / pipe broke).
func (r *Runner) promptNextBack(prompt string) (goBack bool, err error) {
	r.writef("  %s ", prompt)
	input, err := r.readLine()
	if err != nil {
		return false, err
	}
	if strings.ToLower(strings.TrimSpace(input)) == "back" {
		return true, nil
	}
	return false, nil
}

// readLine reads one line from stdin. Returns FATAL error on EOF.
func (r *Runner) readLine() (string, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return "", fmt.Errorf("!!! FATAL: read error during install wizard: %w", err)
		}
		return "", fmt.Errorf("!!! FATAL: install aborted — input stream closed")
	}
	return r.scanner.Text(), nil
}

// writeln writes a line to the UI output.
func (r *Runner) writeln(s string) {
	fmt.Fprintln(r.writer, s)
}

// write writes raw text to the UI output (no newline).
func (r *Runner) write(s string) {
	fmt.Fprint(r.writer, s)
}

// writef writes formatted text to the UI output.
func (r *Runner) writef(format string, args ...interface{}) {
	fmt.Fprintf(r.writer, format, args...)
}

// progressBar returns a simple text progress bar: [████████░░░░] 
func progressBar(pct float64, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct / 100 * float64(width))
	empty := width - filled
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", empty) + "]"
}