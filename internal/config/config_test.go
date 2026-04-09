// config_test.go
// =============================================================================
// GRUG: Tests for the config cave. Verifies TOML parsing, flag merging,
// dep flag parsing, validation, and round-trip TOML serialization.
// =============================================================================

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marshalldavidson61-arch/bindboss/internal/config"
)

// TestLoadMissingFile verifies Load returns defaults when no bindboss.toml exists.
func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("Load on missing file should succeed, got: %v", err)
	}
	// GRUG: Defaults: persist=false, cleanup=true, no run command.
	if cfg.Extract.Persist {
		t.Error("default Persist should be false")
	}
	if !cfg.Extract.Cleanup {
		t.Error("default Cleanup should be true")
	}
	if cfg.Run != "" {
		t.Errorf("default Run should be empty, got %q", cfg.Run)
	}
}

// TestLoadValidTOML verifies a well-formed bindboss.toml is parsed correctly.
func TestLoadValidTOML(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
name = "myapp"
run  = "julia main.jl"
env  = ["JULIA_NUM_THREADS=auto", "DEBUG=1"]

[[needs]]
name    = "julia"
check   = "julia --version"
url     = "https://julialang.org/downloads/"
message = "Julia runtime required"

[extract]
persist = true
cleanup = false
`
	if err := os.WriteFile(filepath.Join(dir, "bindboss.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Name != "myapp" {
		t.Errorf("Name: got %q, want %q", cfg.Name, "myapp")
	}
	if cfg.Run != "julia main.jl" {
		t.Errorf("Run: got %q, want %q", cfg.Run, "julia main.jl")
	}
	if len(cfg.Env) != 2 {
		t.Errorf("Env: got %d items, want 2", len(cfg.Env))
	}
	if len(cfg.Needs) != 1 {
		t.Fatalf("Needs: got %d, want 1", len(cfg.Needs))
	}
	d := cfg.Needs[0]
	if d.Name != "julia" {
		t.Errorf("dep Name: got %q", d.Name)
	}
	if d.Check != "julia --version" {
		t.Errorf("dep Check: got %q", d.Check)
	}
	if d.URL != "https://julialang.org/downloads/" {
		t.Errorf("dep URL: got %q", d.URL)
	}
	if d.Message != "Julia runtime required" {
		t.Errorf("dep Message: got %q", d.Message)
	}
	if !cfg.Extract.Persist {
		t.Error("Extract.Persist should be true")
	}
	if cfg.Extract.Cleanup {
		t.Error("Extract.Cleanup should be false")
	}
}

// TestLoadMalformedTOML verifies that a broken TOML file returns a FATAL error.
func TestLoadMalformedTOML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bindboss.toml"), []byte("[[[[broken"), 0644); err != nil {
		t.Fatalf("write broken toml: %v", err)
	}

	_, err := config.Load(dir)
	if err == nil {
		t.Fatal("Load should fail on malformed TOML but succeeded")
	}
	if !strings.Contains(err.Error(), "FATAL") {
		t.Errorf("error should contain FATAL, got: %v", err)
	}
}

// TestMergeFlagsOverridesConfig verifies that CLI flags win over toml values.
func TestMergeFlagsOverridesConfig(t *testing.T) {
	base := config.Config{
		Name: "from-toml",
		Run:  "julia old.jl",
	}

	merged, err := config.MergeFlags(base, "from-flag", "julia new.jl", nil, true, "/tmp/extract")
	if err != nil {
		t.Fatalf("MergeFlags: %v", err)
	}

	if merged.Name != "from-flag" {
		t.Errorf("Name: got %q, want %q", merged.Name, "from-flag")
	}
	if merged.Run != "julia new.jl" {
		t.Errorf("Run: got %q, want %q", merged.Run, "julia new.jl")
	}
	if !merged.Extract.Persist {
		t.Error("Persist should be true from flag")
	}
	if merged.Extract.Dir != "/tmp/extract" {
		t.Errorf("Dir: got %q", merged.Extract.Dir)
	}
}

// TestMergeFlagsEmptyFlagsKeepsConfig verifies that empty flag values
// don't wipe config values.
func TestMergeFlagsEmptyFlagsKeepsConfig(t *testing.T) {
	base := config.Config{
		Name: "keep-me",
		Run:  "keep-this-run",
	}

	// GRUG: All flags are zero/empty — config should be untouched.
	merged, err := config.MergeFlags(base, "", "", nil, false, "")
	if err != nil {
		t.Fatalf("MergeFlags: %v", err)
	}
	if merged.Name != "keep-me" {
		t.Errorf("Name changed unexpectedly: got %q", merged.Name)
	}
	if merged.Run != "keep-this-run" {
		t.Errorf("Run changed unexpectedly: got %q", merged.Run)
	}
}

// TestParseDepFlagValid verifies correct parsing of all dep flag formats.
func TestParseDepFlagValid(t *testing.T) {
	cases := []struct {
		raw     string
		name    string
		check   string
		url     string
		message string
	}{
		{
			"julia,julia --version,https://julialang.org/downloads/",
			"julia", "julia --version", "https://julialang.org/downloads/", "",
		},
		{
			"bun,bun --version,https://bun.sh,fast JS runtime",
			"bun", "bun --version", "https://bun.sh", "fast JS runtime",
		},
	}

	for _, tc := range cases {
		dep, err := config.ParseDepFlag(tc.raw)
		if err != nil {
			t.Errorf("ParseDepFlag(%q): %v", tc.raw, err)
			continue
		}
		if dep.Name != tc.name {
			t.Errorf("Name: got %q, want %q", dep.Name, tc.name)
		}
		if dep.Check != tc.check {
			t.Errorf("Check: got %q, want %q", dep.Check, tc.check)
		}
		if dep.URL != tc.url {
			t.Errorf("URL: got %q, want %q", dep.URL, tc.url)
		}
		if dep.Message != tc.message {
			t.Errorf("Message: got %q, want %q", dep.Message, tc.message)
		}
	}
}

// TestParseDepFlagInvalid verifies that malformed dep flags produce FATAL errors.
func TestParseDepFlagInvalid(t *testing.T) {
	cases := []string{
		"",                            // empty
		"julia",                       // only name
		"julia,julia --version",       // missing URL
		",julia --version,https://x",  // empty name
	}

	for _, raw := range cases {
		_, err := config.ParseDepFlag(raw)
		if err == nil {
			t.Errorf("ParseDepFlag(%q) should fail but succeeded", raw)
			continue
		}
		if !strings.Contains(err.Error(), "FATAL") {
			t.Errorf("ParseDepFlag(%q) error should contain FATAL, got: %v", raw, err)
		}
	}
}

// TestValidateEmptyRunFails verifies that a config without a run command fails.
func TestValidateEmptyRunFails(t *testing.T) {
	cfg := config.Config{Run: ""}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("Validate should fail on empty run command")
	}
	if !strings.Contains(err.Error(), "FATAL") {
		t.Errorf("Validate error should contain FATAL, got: %v", err)
	}
}

// TestValidateWithRunSucceeds verifies that a config with a run command passes.
func TestValidateWithRunSucceeds(t *testing.T) {
	cfg := config.Config{Run: "julia main.jl"}
	if err := config.Validate(cfg); err != nil {
		t.Errorf("Validate should succeed with run command, got: %v", err)
	}
}

// TestToTOMLRoundTrip verifies that ToTOML produces valid TOML that
// LoadFromBytes can parse back to the same config.
func TestToTOMLRoundTrip(t *testing.T) {
	orig := config.Config{
		Name: "roundtrip",
		Run:  "julia main.jl",
		Env:  []string{"A=1", "B=2"},
		Needs: []config.Dep{
			{Name: "julia", Check: "julia --version", URL: "https://julialang.org/downloads/"},
		},
		Extract: config.Extract{Persist: true, Cleanup: false, Dir: "/tmp/test"},
	}

	data, err := config.ToTOML(orig)
	if err != nil {
		t.Fatalf("ToTOML: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("ToTOML produced empty output")
	}

	roundtripped, err := config.LoadFromBytes(data)
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}

	if roundtripped.Name != orig.Name {
		t.Errorf("Name: got %q, want %q", roundtripped.Name, orig.Name)
	}
	if roundtripped.Run != orig.Run {
		t.Errorf("Run: got %q, want %q", roundtripped.Run, orig.Run)
	}
	if len(roundtripped.Needs) != 1 {
		t.Errorf("Needs count: got %d, want 1", len(roundtripped.Needs))
	}
	if roundtripped.Extract.Persist != orig.Extract.Persist {
		t.Errorf("Extract.Persist: got %v, want %v", roundtripped.Extract.Persist, orig.Extract.Persist)
	}
}
// TestLoadInstallConfig verifies that the [install] section is parsed correctly.
func TestLoadInstallConfig(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
name = "myapp"
run  = "julia main.jl"

[install]
enabled = true
install_file = "install.json"
`
	if err := os.WriteFile(filepath.Join(dir, "bindboss.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Install.Enabled {
		t.Error("Install.Enabled should be true")
	}
	if cfg.Install.ConfigFile != "install.json" {
		t.Errorf("Install.ConfigFile: got %q, want %q", cfg.Install.ConfigFile, "install.json")
	}
}

// TestLoadInstallConfigInline verifies inline install config is parsed.
func TestLoadInstallConfigInline(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
name = "myapp"
run  = "julia main.jl"

[install]
enabled = true
install_config = '{"title":"Test","steps":[{"type":"finish","title":"Done"}]}'
`
	if err := os.WriteFile(filepath.Join(dir, "bindboss.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Install.Enabled {
		t.Error("Install.Enabled should be true")
	}
	if cfg.Install.ConfigInline == "" {
		t.Error("Install.ConfigInline should not be empty")
	}
}

// TestLoadNoInstallSection verifies backward compat — no [install] = defaults.
func TestLoadNoInstallSection(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
name = "oldapp"
run  = "sh run.sh"
`
	if err := os.WriteFile(filepath.Join(dir, "bindboss.toml"), []byte(tomlContent), 0644); err != nil {
		t.Fatalf("write toml: %v", err)
	}

	cfg, err := config.Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// GRUG: no [install] section = Install zero value = Enabled=false.
	if cfg.Install.Enabled {
		t.Error("Install.Enabled should be false when no [install] section exists")
	}
	if cfg.Install.ConfigFile != "" {
		t.Error("Install.ConfigFile should be empty")
	}
}
