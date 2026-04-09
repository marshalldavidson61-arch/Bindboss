// config.go
// =============================================================================
// GRUG: grug put settings in bindboss.toml inside directory before packing.
// stub read toml on extraction. CLI flags override toml. flags always win.
// no toml = fine. grug just need --run flag at minimum.
//
// GRUG: two layer config. toml = author defaults. flags = runner overrides.
// pack time: read toml, merge flags, write merged toml into archive.
// run time: stub read merged toml from extracted dir. done.
//
// GRUG: no global config state. config is a value. callers own their copy.
// pass it around. mutate your copy. don't share mutable config. simple.
//
// -----------------------------------------------------------------------------
// ACADEMIC FOOTER:
// Configuration follows a two-layer merge strategy with clear precedence:
// toml (authoring-time defaults) < CLI flags (invocation-time overrides).
// The merged config is serialized back to TOML and embedded in the archive,
// so the stub always reads a single authoritative bindboss.toml regardless
// of how the binary was packed.
//
// The [hooks] section uses a declarative array-of-strings model rather than
// a scripting language. Each string is parsed as argv (no shell expansion)
// by hooks.splitCmd. This keeps the config readable and the execution surface
// small — shell features require an explicit "sh -c '...'" prefix.
//
// exec_mode controls the Unix exec strategy: "exec" uses syscall.Exec(2)
// which replaces the process image (clean PID, no wrapper, no post_run),
// while "fork" uses os/exec.Cmd.Run() which keeps the stub alive for
// post_run hooks and explicit cleanup. Windows always uses the fork path.
// =============================================================================

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Dep is one runtime dependency grug checks on first run.
// Check exit code 0 = installed. non-zero = missing. no version parsing.
type Dep struct {
	Name    string `toml:"name"`
	Check   string `toml:"check"`
	URL     string `toml:"url"`
	Message string `toml:"message"`
}

// Extract controls where and how the packed directory lands at runtime.
type Extract struct {
	Persist bool   `toml:"persist"` // true = reuse fixed dir across runs (faster for big runtimes)
	Dir     string `toml:"dir"`     // override extract root. empty = use default.
	Cleanup bool   `toml:"cleanup"` // remove tmpdir on exit. ignored when Persist=true.
}

// Hooks is the pre/post command lists. See hooks.go for execution model.
type Hooks struct {
	PreRun  []string `toml:"pre_run"`  // run before dep check + main command
	PostRun []string `toml:"post_run"` // run after main exits — exec_mode=fork ONLY on Unix
}

// Config is the full picture for one packed binary.
type Config struct {
	Name     string  `toml:"name"`      // display name — used in logs and state file path
	Run      string  `toml:"run"`       // command to exec inside extracted dir
	ExecMode string  `toml:"exec_mode"` // "exec" (default) or "fork"
	Env      []string `toml:"env"`      // extra env vars: ["KEY=value", ...]
	Needs    []Dep   `toml:"needs"`     // runtime deps to check on first run
	Extract  Extract `toml:"extract"`
	Hooks    Hooks   `toml:"hooks"`
}

// DefaultConfig returns safe starting values.
// exec=exec, cleanup=true, persist=false.
func DefaultConfig() Config {
	return Config{
		ExecMode: "exec",
		Extract: Extract{
			Persist: false,
			Cleanup: true,
		},
	}
}

// ConfigFileName is the reserved name inside a packed directory.
const ConfigFileName = "bindboss.toml"

// Load reads bindboss.toml from dir. Missing file = fine, return defaults.
// Parse error = FATAL. silent config failure = mysterious runtime behavior.
func Load(dir string) (Config, error) {
	cfg := DefaultConfig()
	path := filepath.Join(dir, ConfigFileName)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil // GRUG: no toml = fine. caller must provide --run.
	}
	if err != nil {
		return cfg, fmt.Errorf("!!! FATAL: cannot read %s: %w", path, err)
	}

	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return cfg, fmt.Errorf("!!! FATAL: cannot parse %s: %w", path, err)
	}

	return cfg, nil
}

// LoadFromBytes parses config from raw TOML bytes.
// Used when loading from embedded archive rather than filesystem.
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

// MergeFlags overlays CLI values onto cfg. Empty string = not provided = keep toml value.
// Flags always win. This is the merge: toml < flags.
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

	for _, raw := range needs {
		dep, err := ParseDepFlag(raw)
		if err != nil {
			return cfg, err
		}
		cfg.Needs = append(cfg.Needs, dep)
	}

	return cfg, nil
}

// ParseDepFlag parses one --needs flag value.
// Format: "name,checkCmd,url" or "name,checkCmd,url,message"
// Fewer than 3 fields = FATAL. Empty name/check/url = FATAL.
func ParseDepFlag(raw string) (Dep, error) {
	// GRUG: split max 4 so message field can contain commas
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

// Validate checks config is complete enough to run.
// Empty run command = FATAL. Bad exec_mode = FATAL.
func Validate(cfg Config) error {
	if strings.TrimSpace(cfg.Run) == "" {
		return fmt.Errorf(
			"!!! FATAL: no run command specified — " +
				"set 'run' in bindboss.toml or pass --run=\"cmd\"")
	}

	switch cfg.ExecMode {
	case "", "exec", "fork":
		// GRUG: empty string treated as "exec" (default). fine.
	default:
		return fmt.Errorf(
			"!!! FATAL: invalid exec_mode %q — must be \"exec\" or \"fork\"", cfg.ExecMode)
	}

	return nil
}

// ToTOML serializes Config to TOML bytes for embedding in the archive.
func ToTOML(cfg Config) ([]byte, error) {
	var sb strings.Builder
	enc := toml.NewEncoder(&sb)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot serialize config to TOML: %w", err)
	}
	return []byte(sb.String()), nil
}