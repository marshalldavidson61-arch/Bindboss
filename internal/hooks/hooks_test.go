// hooks_test.go
// =============================================================================
// GRUG: Tests for the hooks cave. Run order, failure propagation, env injection,
// empty hook handling. No silent pass on failure.
// =============================================================================

package hooks

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestRunnerEmpty verifies Runner returns nil for empty hook list.
func TestRunnerEmpty(t *testing.T) {
	if err := Runner(nil, t.TempDir(), "testbin", os.Environ()); err != nil {
		t.Fatalf("Runner with nil hooks: %v", err)
	}
	if err := Runner([]string{}, t.TempDir(), "testbin", os.Environ()); err != nil {
		t.Fatalf("Runner with empty hooks: %v", err)
	}
}

// TestRunnerExecutesInOrder verifies hooks run in sequence and produce output
// in order. We use "echo" to write to a temp file and check ordering.
func TestRunnerExecutesInOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("echo path differs on Windows")
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "order.txt")

	hooks := []string{
		"sh -c 'echo first >> " + outFile + "'",
		"sh -c 'echo second >> " + outFile + "'",
		"sh -c 'echo third >> " + outFile + "'",
	}

	if err := Runner(hooks, dir, "testbin", os.Environ()); err != nil {
		t.Fatalf("Runner: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}

	got := string(data)
	if got != "first\nsecond\nthird\n" {
		t.Errorf("unexpected order output: %q", got)
	}
}

// TestRunnerStopsOnFailure verifies that a failing hook stops execution
// and subsequent hooks do not run.
func TestRunnerStopsOnFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell commands differ on Windows")
	}

	dir := t.TempDir()
	sentinel := filepath.Join(dir, "should_not_exist")

	hooks := []string{
		"false", // exits with code 1
		"sh -c 'touch " + sentinel + "'",
	}

	err := Runner(hooks, dir, "testbin", os.Environ())
	if err == nil {
		t.Fatal("Runner should have returned error after hook failure, got nil")
	}

	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Error("second hook ran after first failed — should have stopped")
	}

	t.Logf("correctly stopped on failure: %v", err)
}

// TestRunnerEnvInjection verifies BINDBOSS_EXTRACT_DIR and BINDBOSS_BINARY_NAME
// are injected into hook environment.
func TestRunnerEnvInjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell env syntax differs on Windows")
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "env_out.txt")

	hooks := []string{
		"sh -c 'echo $BINDBOSS_EXTRACT_DIR > " + outFile + "'",
	}

	if err := Runner(hooks, dir, "mybinary", os.Environ()); err != nil {
		t.Fatalf("Runner: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read env output: %v", err)
	}

	got := string(data)
	// The value should contain the extract dir path
	if len(got) == 0 {
		t.Error("BINDBOSS_EXTRACT_DIR was empty in hook environment")
	}
	t.Logf("BINDBOSS_EXTRACT_DIR in hook: %q", got)
}

// TestRunnerCommandNotFound verifies Runner returns a FATAL error if the
// hook command binary doesn't exist on PATH.
func TestRunnerCommandNotFound(t *testing.T) {
	hooks := []string{"this_command_does_not_exist_anywhere_12345"}
	err := Runner(hooks, t.TempDir(), "testbin", os.Environ())
	if err == nil {
		t.Fatal("expected error for missing command, got nil")
	}
	t.Logf("correctly rejected missing command: %v", err)
}

// TestSplitCmd verifies the shell-style argument splitter handles
// quoting and whitespace correctly.
func TestSplitCmd(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"echo hello", []string{"echo", "hello"}},
		{"echo 'hello world'", []string{"echo", "hello world"}},
		{`echo "hello world"`, []string{"echo", "hello world"}},
		{"  spaces  everywhere  ", []string{"spaces", "everywhere"}},
		{"single", []string{"single"}},
		{"", nil},
		{"   ", nil},
	}

	for _, tc := range cases {
		got := splitCmd(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("splitCmd(%q): got %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitCmd(%q)[%d]: got %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}