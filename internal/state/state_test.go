// state_test.go
// =============================================================================
// GRUG: Tests for the state cave. Verifies read/write/reset of first-run
// state files and atomic write behavior.
// =============================================================================

package state_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marshalldavidson61-arch/bindboss/internal/state"
)

// overrideHome redirects os.UserHomeDir to a temp dir for isolated testing.
// Returns a cleanup function that restores the original HOME.
func overrideHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)        // Linux/macOS
	t.Setenv("USERPROFILE", tmp) // Windows
	return tmp
}

// TestLoadMissingState verifies that loading a non-existent state returns
// Checked=false with no error (first-run condition).
func TestLoadMissingState(t *testing.T) {
	overrideHome(t)

	s, err := state.Load("testapp")
	if err != nil {
		t.Fatalf("Load on missing state: %v", err)
	}
	if s.Checked {
		t.Error("missing state should return Checked=false")
	}
	if s.CheckedAt != 0 {
		t.Errorf("missing state should return CheckedAt=0, got %d", s.CheckedAt)
	}
}

// TestMarkCheckedAndLoad verifies that MarkChecked writes state that
// loads back as Checked=true.
func TestMarkCheckedAndLoad(t *testing.T) {
	overrideHome(t)

	if err := state.MarkChecked("myapp"); err != nil {
		t.Fatalf("MarkChecked: %v", err)
	}

	s, err := state.Load("myapp")
	if err != nil {
		t.Fatalf("Load after MarkChecked: %v", err)
	}
	if !s.Checked {
		t.Error("state should be Checked=true after MarkChecked")
	}
	if s.CheckedAt <= 0 {
		t.Errorf("CheckedAt should be a positive unix timestamp, got %d", s.CheckedAt)
	}
}

// TestResetClearsState verifies that Reset makes the next Load return Checked=false.
func TestResetClearsState(t *testing.T) {
	overrideHome(t)

	if err := state.MarkChecked("resetme"); err != nil {
		t.Fatalf("MarkChecked: %v", err)
	}

	s, _ := state.Load("resetme")
	if !s.Checked {
		t.Fatal("setup: state should be Checked=true before reset")
	}

	if err := state.Reset("resetme"); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	s2, err := state.Load("resetme")
	if err != nil {
		t.Fatalf("Load after Reset: %v", err)
	}
	if s2.Checked {
		t.Error("state should be Checked=false after Reset")
	}
}

// TestResetNonExistentIsOK verifies that Reset on a nonexistent state
// is not an error.
func TestResetNonExistentIsOK(t *testing.T) {
	overrideHome(t)

	if err := state.Reset("ghost"); err != nil {
		t.Errorf("Reset on nonexistent state should be OK, got: %v", err)
	}
}

// TestStateDirCreated verifies that ~/.bindboss/ is created on first use.
func TestStateDirCreated(t *testing.T) {
	home := overrideHome(t)

	if err := state.MarkChecked("dirtest"); err != nil {
		t.Fatalf("MarkChecked: %v", err)
	}

	stateDir := filepath.Join(home, ".bindboss")
	fi, err := os.Stat(stateDir)
	if err != nil {
		t.Fatalf("~/.bindboss should be created, got: %v", err)
	}
	if !fi.IsDir() {
		t.Error("~/.bindboss should be a directory")
	}
}

// TestSeparateNamesAreSeparate verifies that two different binary names
// have independent state files.
func TestSeparateNamesAreSeparate(t *testing.T) {
	overrideHome(t)

	if err := state.MarkChecked("app-a"); err != nil {
		t.Fatalf("MarkChecked app-a: %v", err)
	}

	sa, _ := state.Load("app-a")
	sb, _ := state.Load("app-b")

	if !sa.Checked {
		t.Error("app-a should be Checked=true")
	}
	if sb.Checked {
		t.Error("app-b should be Checked=false (never marked)")
	}
}

// TestEmptyNameFails verifies that an empty binary name returns a FATAL error.
func TestEmptyNameFails(t *testing.T) {
	overrideHome(t)

	_, err := state.Load("")
	if err == nil {
		t.Fatal("Load with empty name should fail")
	}
	if !strings.Contains(err.Error(), "FATAL") {
		t.Errorf("error should contain FATAL, got: %v", err)
	}
}
// TestMarkUpdateCheckedAndLoad verifies that MarkUpdateChecked persists and loads
// update-related fields correctly.
func TestMarkUpdateCheckedAndLoad(t *testing.T) {
	name := "test-update-state"

	// First, mark dep checked so we have a base state
	if err := state.MarkChecked(name); err != nil {
		t.Fatalf("MarkChecked: %v", err)
	}

	// Now mark update checked
	if err := state.MarkUpdateChecked(name, "abc123def456"); err != nil {
		t.Fatalf("MarkUpdateChecked: %v", err)
	}

	s, err := state.Load(name)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Dep state should still be preserved
	if !s.Checked {
		t.Error("Checked should still be true after MarkUpdateChecked")
	}
	if s.CheckedAt == 0 {
		t.Error("CheckedAt should not be zero after MarkChecked")
	}

	// Update state should be set
	if s.UpdateCommitSHA != "abc123def456" {
		t.Errorf("UpdateCommitSHA: got %q, want %q", s.UpdateCommitSHA, "abc123def456")
	}
	if s.UpdateCheckedAt == 0 {
		t.Error("UpdateCheckedAt should not be zero after MarkUpdateChecked")
	}
}

// TestMarkUpdateCheckedOverwritesSHA verifies that a second update check
// replaces the old commit SHA.
func TestMarkUpdateCheckedOverwritesSHA(t *testing.T) {
	name := "test-update-overwrite"

	if err := state.MarkUpdateChecked(name, "first-sha"); err != nil {
		t.Fatalf("first MarkUpdateChecked: %v", err)
	}

	s1, err := state.Load(name)
	if err != nil {
		t.Fatalf("Load after first: %v", err)
	}
	if s1.UpdateCommitSHA != "first-sha" {
		t.Fatalf("first SHA: got %q, want %q", s1.UpdateCommitSHA, "first-sha")
	}

	if err := state.MarkUpdateChecked(name, "second-sha"); err != nil {
		t.Fatalf("second MarkUpdateChecked: %v", err)
	}

	s2, err := state.Load(name)
	if err != nil {
		t.Fatalf("Load after second: %v", err)
	}
	if s2.UpdateCommitSHA != "second-sha" {
		t.Errorf("second SHA: got %q, want %q", s2.UpdateCommitSHA, "second-sha")
	}
}

// TestStateRoundTripWithUpdate verifies serialize/parse round-trip with update fields.
func TestStateRoundTripWithUpdate(t *testing.T) {
	original := state.State{
		Checked:         true,
		CheckedAt:       1234567890,
		UpdateCommitSHA: "abc123def456",
		UpdateCheckedAt: 1234567900,
	}

	name := "test-roundtrip-update"
	if err := state.Save(name, original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := state.Load(name)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Checked != original.Checked {
		t.Errorf("Checked: got %v, want %v", loaded.Checked, original.Checked)
	}
	if loaded.CheckedAt != original.CheckedAt {
		t.Errorf("CheckedAt: got %d, want %d", loaded.CheckedAt, original.CheckedAt)
	}
	if loaded.UpdateCommitSHA != original.UpdateCommitSHA {
		t.Errorf("UpdateCommitSHA: got %q, want %q", loaded.UpdateCommitSHA, original.UpdateCommitSHA)
	}
	if loaded.UpdateCheckedAt != original.UpdateCheckedAt {
		t.Errorf("UpdateCheckedAt: got %d, want %d", loaded.UpdateCheckedAt, original.UpdateCheckedAt)
	}
}
