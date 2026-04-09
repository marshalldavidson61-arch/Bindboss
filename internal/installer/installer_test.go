// installer_test.go
// =============================================================================
// GRUG: Tests for the install wizard. Uses fake I/O to simulate user input.
// No real terminal needed — everything goes through bufio.Scanner and io.Writer.
//
// ---
// ACADEMIC: Tests use NewRunnerWithIO to inject controlled input streams,
// enabling deterministic testing of the interactive wizard flow without
// requiring a PTY or terminal emulator. The output writer captures all
// rendered UI for assertion.
// =============================================================================

package installer

import (
	"bytes"
	"strings"
	"testing"
)

func TestParse_Valid(t *testing.T) {
	jsonData := `{
		"title": "Test App",
		"version": "1.0",
		"steps": [
			{"type": "welcome", "title": "Welcome", "content": "Hello!"},
			{"type": "message", "title": "Info", "content": "Some info."},
			{"type": "finish", "title": "Done"}
		]
	}`
	cfg, err := Parse([]byte(jsonData))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if cfg.Title != "Test App" {
		t.Errorf("title: got %q, want %q", cfg.Title, "Test App")
	}
	if len(cfg.Steps) != 3 {
		t.Errorf("steps: got %d, want 3", len(cfg.Steps))
	}
}

func TestParse_UnknownType(t *testing.T) {
	jsonData := `{
		"title": "Bad",
		"steps": [{"type": "banana", "title": "Oops"}]
	}`
	_, err := Parse([]byte(jsonData))
	if err == nil {
		t.Fatal("Parse should fail on unknown step type")
	}
	if !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("error should mention unknown type, got: %v", err)
	}
}

func TestParse_EmptySteps(t *testing.T) {
	jsonData := `{"title": "Empty", "steps": []}`
	_, err := Parse([]byte(jsonData))
	if err == nil {
		t.Fatal("Parse should fail on empty steps")
	}
	if !strings.Contains(err.Error(), "no steps") {
		t.Errorf("error should mention no steps, got: %v", err)
	}
}

func TestParse_DepsWithoutDeps(t *testing.T) {
	jsonData := `{
		"title": "Bad",
		"steps": [{"type": "deps", "title": "Install", "deps": []}]
	}`
	_, err := Parse([]byte(jsonData))
	if err == nil {
		t.Fatal("Parse should fail on deps step with no deps")
	}
}

func TestParse_LicenseWithoutContent(t *testing.T) {
	jsonData := `{
		"title": "Bad",
		"steps": [{"type": "license", "title": "License", "content": ""}]
	}`
	_, err := Parse([]byte(jsonData))
	if err == nil {
		t.Fatal("Parse should fail on license step with no content")
	}
}

func TestParse_DepValidation(t *testing.T) {
	// GRUG: dep with empty name should fail
	jsonData := `{
		"title": "Bad",
		"steps": [{
			"type": "deps", "title": "Install",
			"deps": [{"name": "", "check": "test", "download_url": "http://x"}]
		}]
	}`
	_, err := Parse([]byte(jsonData))
	if err == nil {
		t.Fatal("Parse should fail on dep with empty name")
	}

	// dep with empty check should fail
	jsonData2 := `{
		"title": "Bad",
		"steps": [{
			"type": "deps", "title": "Install",
			"deps": [{"name": "foo", "check": "", "download_url": "http://x"}]
		}]
	}`
	_, err = Parse([]byte(jsonData2))
	if err == nil {
		t.Fatal("Parse should fail on dep with empty check")
	}

	// dep with no URLs should fail
	jsonData3 := `{
		"title": "Bad",
		"steps": [{
			"type": "deps", "title": "Install",
			"deps": [{"name": "foo", "check": "foo --version", "download_url": "", "fallback_url": ""}]
		}]
	}`
	_, err = Parse([]byte(jsonData3))
	if err == nil {
		t.Fatal("Parse should fail on dep with no download_url or fallback_url")
	}
}

func TestParse_MalformedJSON(t *testing.T) {
	_, err := Parse([]byte("{bad json"))
	if err == nil {
		t.Fatal("Parse should fail on malformed JSON")
	}
	if !strings.Contains(err.Error(), "cannot parse") {
		t.Errorf("error should mention parse failure, got: %v", err)
	}
}

func TestRunner_WelcomeAndFinish(t *testing.T) {
	// GRUG: simplest wizard — welcome + finish. user hits Enter twice.
	cfg := &InstallConfig{
		Title:   "Test",
		Version: "1.0",
		Steps: []Step{
			{Type: "welcome", Title: "Welcome", Content: "Hello World!"},
			{Type: "finish", Title: "Done", Content: "All done!"},
		},
	}

	input := strings.NewReader("\n\n")
	var output bytes.Buffer

	runner := NewRunnerWithIO(cfg, input, &output)
	err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	out := output.String()
	if !strings.Contains(out, "Test") {
		t.Error("output should contain the title")
	}
	if !strings.Contains(out, "Hello World!") {
		t.Error("output should contain welcome content")
	}
	if !strings.Contains(out, "All done!") {
		t.Error("output should contain finish content")
	}
	if !strings.Contains(out, "Step 1/2") {
		t.Error("output should show step indicator")
	}
}

func TestRunner_LicenseAccept(t *testing.T) {
	cfg := &InstallConfig{
		Title: "Test",
		Steps: []Step{
			{Type: "license", Title: "License", Content: "MIT License blah blah"},
			{Type: "finish", Title: "Done"},
		},
	}

	// First type "no", then "accept"
	input := strings.NewReader("no\naccept\n")
	var output bytes.Buffer

	runner := NewRunnerWithIO(cfg, input, &output)
	err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	out := output.String()
	if !strings.Contains(out, "MIT License") {
		t.Error("output should show license text")
	}
	if !strings.Contains(out, "License accepted") {
		t.Error("output should confirm acceptance")
	}
}

func TestRunner_LicenseBack(t *testing.T) {
	cfg := &InstallConfig{
		Title: "Test",
		Steps: []Step{
			{Type: "welcome", Title: "Welcome", Content: "Hi"},
			{Type: "license", Title: "License", Content: "Some license"},
			{Type: "finish", Title: "Done"},
		},
	}

	// Go forward from welcome, type "back" at license, Enter at welcome again,
	// then accept license, then finish
	input := strings.NewReader("\nback\n\naccept\n")
	var output bytes.Buffer

	runner := NewRunnerWithIO(cfg, input, &output)
	err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	out := output.String()
	// GRUG: welcome should appear twice (initial + back)
	if strings.Count(out, "Step 1/3") < 2 {
		t.Error("welcome step should appear at least twice (initial + after back)")
	}
}

func TestRunner_MessageStep(t *testing.T) {
	cfg := &InstallConfig{
		Title: "Test",
		Steps: []Step{
			{Type: "message", Title: "Info", Content: "Important info here."},
			{Type: "finish", Title: "Done"},
		},
	}

	input := strings.NewReader("\n")
	var output bytes.Buffer

	runner := NewRunnerWithIO(cfg, input, &output)
	err := runner.Run()
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if !strings.Contains(output.String(), "Important info here.") {
		t.Error("output should contain message content")
	}
}

func TestRunner_AbortOnEOF(t *testing.T) {
	cfg := &InstallConfig{
		Title: "Test",
		Steps: []Step{
			{Type: "welcome", Title: "Welcome", Content: "Hi"},
			{Type: "message", Title: "Never reached"},
		},
	}

	// GRUG: empty input = EOF immediately at first prompt
	input := strings.NewReader("")
	var output bytes.Buffer

	runner := NewRunnerWithIO(cfg, input, &output)
	err := runner.Run()
	if err == nil {
		t.Fatal("Run should fail on EOF")
	}
	if !strings.Contains(err.Error(), "aborted") {
		t.Errorf("error should mention abort, got: %v", err)
	}
}

func TestProgressBar(t *testing.T) {
	tests := []struct {
		pct  float64
		want string
	}{
		{0, "[░░░░░░░░░░]"},
		{50, "[█████░░░░░]"},
		{100, "[██████████]"},
		{-10, "[░░░░░░░░░░]"},
		{200, "[██████████]"},
	}
	for _, tt := range tests {
		got := progressBar(tt.pct, 10)
		if got != tt.want {
			t.Errorf("progressBar(%.0f, 10) = %q, want %q", tt.pct, got, tt.want)
		}
	}
}