// state.go
// =============================================================================
// GRUG: This is the state cave. Tracks which bindboss-packed binaries have
// already passed their first-run dependency check. Once a binary runs clean,
// we write a state file so subsequent runs skip the dep check entirely.
//
// ACADEMIC: First-run state is persisted to ~/.bindboss/<name>.state as a
// simple key=value text file. JSON or TOML would be overkill — the state
// only needs two fields: "checked" (bool) and "checked_at" (unix timestamp).
// The file is created atomically (write to temp, rename) to avoid partial
// writes from a crash during the first-run sequence.
//
// Users can run `bindboss reset <name>` to delete the state file and force
// the dep check to run again (useful after a fresh OS install).
// =============================================================================

package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// State holds the persisted first-run state for a packed binary.
type State struct {
	// Checked: true if the dependency check has passed at least once.
	Checked bool
	// CheckedAt: unix timestamp of when the check last passed.
	CheckedAt int64
}

// stateDir returns the ~/.bindboss/ directory, creating it if needed.
func stateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("!!! FATAL: cannot find home directory for state storage: %w", err)
	}
	dir := filepath.Join(home, ".bindboss")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("!!! FATAL: cannot create state directory %q: %w", dir, err)
	}
	return dir, nil
}

// statePath returns the full path to the state file for the named binary.
func statePath(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("!!! FATAL: state file lookup requires a non-empty binary name")
	}
	dir, err := stateDir()
	if err != nil {
		return "", err
	}
	// GRUG: Sanitize name — no path separators, no dots that could escape dir.
	safe := strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == 0 {
			return '_'
		}
		return r
	}, name)
	return filepath.Join(dir, safe+".state"), nil
}

// Load reads the state file for the named binary.
// Returns a zeroed State (Checked=false) if the file does not exist.
// Returns an error if the file exists but is malformed.
func Load(name string) (State, error) {
	path, err := statePath(name)
	if err != nil {
		return State{}, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// GRUG: No state file = first run. Not an error.
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("!!! FATAL: cannot read state file %q: %w", path, err)
	}

	return parse(data)
}

// Save writes the state file for the named binary atomically.
// Creates ~/.bindboss/ if it doesn't exist.
func Save(name string, s State) error {
	path, err := statePath(name)
	if err != nil {
		return err
	}

	content := serialize(s)

	// GRUG: Write to temp file in the same directory, then atomic rename.
	// Crash during write leaves the old state file intact.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bindboss-state-*")
	if err != nil {
		return fmt.Errorf("!!! FATAL: cannot create temp file for state write: %w", err)
	}
	tmpPath := tmp.Name()

	defer os.Remove(tmpPath) // no-op after successful rename

	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("!!! FATAL: cannot write state to temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("!!! FATAL: cannot flush state temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("!!! FATAL: cannot atomically write state file %q: %w", path, err)
	}

	return nil
}

// Reset deletes the state file for the named binary.
// Subsequent runs will treat it as a first run and re-check dependencies.
// Not an error if the file doesn't exist.
func Reset(name string) error {
	path, err := statePath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("!!! FATAL: cannot delete state file %q: %w", path, err)
	}
	return nil
}

// MarkChecked saves a State with Checked=true and CheckedAt=now.
func MarkChecked(name string) error {
	return Save(name, State{
		Checked:   true,
		CheckedAt: time.Now().Unix(),
	})
}

// serialize converts a State to the simple key=value text format.
func serialize(s State) string {
	return fmt.Sprintf("checked=%v\nchecked_at=%d\n", s.Checked, s.CheckedAt)
}

// parse reads the simple key=value text format back into a State.
func parse(data []byte) (State, error) {
	s := State{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return State{}, fmt.Errorf("!!! FATAL: malformed state file line: %q", line)
		}
		k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch k {
		case "checked":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return State{}, fmt.Errorf("!!! FATAL: invalid 'checked' value in state file: %q", v)
			}
			s.Checked = b
		case "checked_at":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return State{}, fmt.Errorf("!!! FATAL: invalid 'checked_at' value in state file: %q", v)
			}
			s.CheckedAt = n
		}
	}
	return s, nil
}