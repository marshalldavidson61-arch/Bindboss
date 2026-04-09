// config.go
// =============================================================================
// GRUG: This is the config cave. Reads bindboss.toml from the packed directory
// and merges it with CLI flags. CLI flags always win — config is the fallback.
//
// ACADEMIC: Configuration follows a two-layer merge strategy. The on-disk
// bindboss.toml provides authoring-time defaults (run command, deps, extract
// behavior). CLI flags at invocation time override any field. This allows
// the same packed binary to be re-run with different flags without repacking.
//
// Config is parsed once at startup and passed as a value through the call chain.
// No global config state — callers own their copy.
// =============================================================================

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Dep describes a runtime dependency the packed binary requires before running.
// Check is a shell command whose exit code determines presence (0 = found).
// URL is shown to the user and opened in the browser if the dep is missing.
// Message is an optional human-readable note shown alongside the URL.
type Dep struct {
	Name    string `toml:"name"`
	Check   string `toml:"check"`
	URL     string `toml:"url"`
	Message string `toml:"message"`
}

// Extract controls where and how the packed directory is unpacked at runtime.
type Extract struct {
	// Persist: if true, extract once to a fixed directory (~/.bindboss/<name>/)
	// and reuse on subsequent runs. Faster for large runtimes (e.g. Julia).
	// If false, extract to a fresh tmpdir and clean up on exit.
	Persist bool `toml:"persist"`

	// Dir: override the extract root. Empty = use ~/.bindboss/<name>/ (persist)
	// or os.TempDir() (non-persist).
	Dir string `toml:"dir"`

	// Cleanup: remove tmpdir on exit. Ignored when Persist=true.
	Cleanup bool `toml:"cleanup"`
}

// Config is the full bindboss configuration for a packed binary.
// It is populated from bindboss.toml (if present in the packed dir)
// and then overridden by any CLI flags passed at pack or run time.
type Config struct {
	// Name: the binary's display name. Used in log messages and state file path.
	Name string `toml:"name"`

	// Run: the command to execute inside the extracted directory.
	// Example: "julia main.jl" or "bun run index.ts"
	Run string `toml:"run"`

	// Env: additional environment variables to set before running.
	// Format: ["KEY=value", "OTHER=value2"]
	Env []string `toml:"env"`

	// Needs: list of runtime dependencies to check on first run.
	Needs []Dep `toml:"needs"`

	// Extract: controls extraction behavior.
	Extract Extract `toml:"extract"`
}

// DefaultConfig returns a Config with safe defaults.
// Cleanup=true keeps the host tidy. Persist=false is conservative.
func DefaultConfig() Config {
	return Config{
		Extract: Extract{
			Persist: false,
			Cleanup: true,
		},
	}
}

// ConfigFileName is the reserved filename inside a packed directory.
const ConfigFileName = "bindboss.toml"

// Load reads bindboss.toml from dir. If the file does not exist, returns
// DefaultConfig with no error — a config file is optional.
// Any other read or parse error is fatal: silent config failures cause
// mysterious runtime behavior.
func Load(dir string) (Config, error) {
	cfg := DefaultConfig()
	path := filepath.Join(dir, ConfigFileName)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// GRUG: No config file is fine. Caller must provide --run flag.
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("!!! FATAL: cannot read %s: %w", path, err)
	}

	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return cfg, fmt.Errorf("!!! FATAL: cannot parse %s: %w", path, err)
	}

	return cfg, nil
}

// LoadFromBytes parses config from raw TOML bytes (used when loading from
// the embedded archive rather than the filesystem).
func LoadFromBytes(data []byte) (Config, error) {
	cfg := DefaultConfig()
	if len(data) == 0 {
		return cfg, nil
	}
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return cfg, fmt.Errorf("!!! FATAL: cannot parse embedded bindboss.toml: %w", err)
	}
	return cfg, nil
}

// MergeFlags overlays CLI-provided values onto cfg.
// Only non-zero values from flags overwrite — empty string means "not provided".
// This is the merge: toml < flags. Flags always win.
func MergeFlags(cfg Config, name, run string, needs []string, persist bool, dir string) (Config, error) {
	if name != "" {
		cfg.Name = name
	}
	if run != "" {
		cfg.Run = run
	}
	if persist {
		cfg.Extract.Persist = true
	}
	if dir != "" {
		cfg.Extract.Dir = dir
	}

	// GRUG: Parse --needs flags. Each flag is "name,checkCmd,url" or
	// "name,checkCmd,url,message". Comma-separated. Simple and unambiguous.
	for _, raw := range needs {
		dep, err := ParseDepFlag(raw)
		if err != nil {
			return cfg, err
		}
		cfg.Needs = append(cfg.Needs, dep)
	}

	return cfg, nil
}

// ParseDepFlag parses a --needs flag value of the form:
//
//	"name,checkCmd,url"
//	"name,checkCmd,url,optional message"
//
// Returns an error if fewer than 3 fields are present.
// Example: "julia,julia --version,https://julialang.org/downloads/"
func ParseDepFlag(raw string) (Dep, error) {
	// GRUG: Split on comma but allow commas inside the message field (last field).
	// So we split into at most 4 parts.
	parts := strings.SplitN(raw, ",", 4)
	if len(parts) < 3 {
		return Dep{}, fmt.Errorf(
			"!!! FATAL: --needs flag needs at least 3 comma-separated fields: "+
				"name,checkCmd,url — got %q", raw)
	}

	d := Dep{
		Name:  strings.TrimSpace(parts[0]),
		Check: strings.TrimSpace(parts[1]),
		URL:   strings.TrimSpace(parts[2]),
	}
	if len(parts) == 4 {
		d.Message = strings.TrimSpace(parts[3])
	}

	if d.Name == "" {
		return Dep{}, fmt.Errorf("!!! FATAL: --needs dep name cannot be empty in %q", raw)
	}
	if d.Check == "" {
		return Dep{}, fmt.Errorf("!!! FATAL: --needs check command cannot be empty in %q", raw)
	}
	if d.URL == "" {
		return Dep{}, fmt.Errorf("!!! FATAL: --needs URL cannot be empty in %q", raw)
	}

	return d, nil
}

// Validate checks that a Config is complete enough to run.
// Returns an error if the run command is empty — that's the only hard requirement.
func Validate(cfg Config) error {
	if strings.TrimSpace(cfg.Run) == "" {
		return fmt.Errorf(
			"!!! FATAL: no run command specified — " +
				"set 'run' in bindboss.toml or pass --run=\"cmd\"")
	}
	return nil
}

// ToTOML serializes a Config to TOML bytes for embedding in a packed binary.
func ToTOML(cfg Config) ([]byte, error) {
	var sb strings.Builder
	enc := toml.NewEncoder(&sb)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot serialize config to TOML: %w", err)
	}
	return []byte(sb.String()), nil
}