// checker_test.go
// =============================================================================
// GRUG: Tests for the dependency checker cave. Verifies check command parsing,
// presence detection using real system commands, and the splitCmd tokenizer.
// We don't test the interactive browser+wait loop (that needs stdin mocking)
// but we do test the underlying isPresent oracle and splitCmd parser.
// =============================================================================

package checker_test

import (
	"testing"

	"github.com/marshalldavidson61-arch/bindboss/internal/checker"
)

// TestSplitCmdBasic verifies basic tokenization of command strings.
func TestSplitCmdBasic(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"julia --version", []string{"julia", "--version"}},
		{"bun run index.ts", []string{"bun", "run", "index.ts"}},
		{"echo hello world", []string{"echo", "hello", "world"}},
		{`"quoted arg"`, []string{"quoted arg"}},
		{`cmd "hello world" bare`, []string{"cmd", "hello world", "bare"}},
		{"  spaces  around  ", []string{"spaces", "around"}},
		{"", nil},
		{"   ", nil},
	}

	for _, tc := range cases {
		got := checker.SplitCmd(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("SplitCmd(%q): got %v (len %d), want %v (len %d)",
				tc.input, got, len(got), tc.want, len(tc.want))
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("SplitCmd(%q)[%d]: got %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

// TestIsPresentTrueForEcho verifies that a command that always exits 0
// (echo) is detected as present.
func TestIsPresentTrueForEcho(t *testing.T) {
	// GRUG: "echo" is available on every POSIX system and always exits 0.
	if !checker.IsPresent("echo hello") {
		t.Error("IsPresent(\"echo hello\") should be true — echo is always available")
	}
}

// TestIsPresentFalseForGibberish verifies that a command that doesn't exist
// returns false, not an error or panic.
func TestIsPresentFalseForGibberish(t *testing.T) {
	if checker.IsPresent("thisdoesnotexist_bindboss_test_xyz") {
		t.Error("IsPresent on nonexistent command should return false")
	}
}

// TestIsPresentFalseForFailingCommand verifies that a command that exists
// but exits nonzero is treated as absent.
func TestIsPresentFalseForFailingCommand(t *testing.T) {
	// GRUG: "false" is a POSIX command that always exits 1.
	if checker.IsPresent("false") {
		t.Error("IsPresent(\"false\") should return false — false always exits 1")
	}
}

// TestIsPresentEmptyCommand verifies that an empty check command returns false.
func TestIsPresentEmptyCommandReturnsFalse(t *testing.T) {
	if checker.IsPresent("") {
		t.Error("IsPresent(\"\") should return false")
	}
}