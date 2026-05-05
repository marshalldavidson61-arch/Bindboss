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
// The [install] section enables an optional JSON-driven install wizard GUI
// that replaces the raw dep-check-and-open-browser flow with a guided
// multi-step installer. The wizard config can be inlined as a JSON string
// or referenced as a file path relative to the packed directory.
//
// The [update] section enables remote update checking from a Git repository.
// The stub queries the GitHub API for the latest commit on the configured
// branch. If the commit SHA differs from the one stored in the state file,
// the stub downloads the latest archive zip and re-extracts. This provides
// automatic updates without repacking — the binary acts as a thin launcher
// that always runs the latest version from the remote repo.
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

// Install configures the JSON-driven install wizard GUI.
// When present, the stub runs a guided installer on first run instead of the
// raw dep-check-and-open-browser flow. The install config can be an inline
// JSON string or a path to an install.json file inside the packed directory.
//
// GRUG: install_config = inline JSON. install_file = path to JSON file.
// pick one. if both set, install_config wins. if neither set, no wizard.
type Install struct {
	Enabled      bool   `toml:"enabled"`        // master switch — false = skip wizard entirely
	ConfigInline string `toml:"install_config"` // inline JSON string with wizard definition
	ConfigFile   string `toml:"install_file"`   // path to install.json relative to packed dir
}

// Update configures remote update checking from a Git repository.
// When present, the stub checks the repo for new commits on every run.
// If the remote has new commits since the last run, the stub downloads
// the latest archive and re-extracts into the persist directory.
//
// GRUG: update URL = where grug checks for new stuff. if remote has new
// commits, grug downloads fresh zip and replaces old files. simple.
// no update URL = no checking. binary stays as packed forever. fine too.
//
// GRUG: update requires persist mode. without persist, every run extracts
// fresh from the embedded payload anyway — update check is pointless.
// if you set update URL without persist, grug auto-enables persist and warns.
//
// GRUG: right now grug only speaks GitHub. URL must be https://github.com/owner/repo.
// other git hosts = future work. one host, done right, then extend.
type Update struct {
	URL    string `toml:"url"`    // GitHub repo URL, e.g. "https://github.com/owner/repo"
	Branch string `toml:"branch"` // branch to track. empty = "main"
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
	Install  Install `toml:"install"` // optional install wizard GUI config
	Update   Update  `toml:"update"`  // optional remote update checker config
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

// MergeUpdateFlags overlays update-related CLI values onto cfg.
// GRUG: separate from MergeFlags because update has its own --update flag.
// empty string = not provided = keep toml value. flag always wins.
func MergeUpdateFlags(cfg Config, updateURL, updateBranch string) Config {
	if updateURL != "" {
		cfg.Update.URL = updateURL
	}
	if updateBranch != "" {
		cfg.Update.Branch = updateBranch
	}
	return cfg
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

// ParseUpdateURL validates a GitHub repo URL.
// Must be https://github.com/owner/repo format.
// Returns the URL as-is if valid, or a FATAL error.
//
// GRUG: grug only speaks GitHub. URL must look like a GitHub repo.
// no git:// no ssh:// no bitbucket. just https://github.com/owner/repo.
// trailing slash = fine. .git suffix = fine. grug strips both.
func ParseUpdateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil // GRUG: empty = no update. not an error.
	}

	// GRUG: strip trailing slash and .git suffix. normalize for API calls.
	raw = strings.TrimSuffix(raw, "/")
	raw = strings.TrimSuffix(raw, ".git")

	if !strings.HasPrefix(raw, "https://github.com/") {
		return "", fmt.Errorf(
			"!!! FATAL: --update URL must be a GitHub repo (https://github.com/owner/repo), got %q",
			raw)
	}

	// GRUG: must have exactly owner/repo after the prefix.
	path := strings.TrimPrefix(raw, "https://github.com/")
	parts := strings.Split(path, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf(
			"!!! FATAL: --update URL must be https://github.com/owner/repo, got %q", raw)
	}

	return raw, nil
}

// Validate checks config is complete enough to run.
// Empty run command = FATAL. Bad exec_mode = FATAL.
// Update without persist = auto-enable persist and warn.
func Validate(cfg Config) (Config, error) {
	if strings.TrimSpace(cfg.Run) == "" {
		return cfg, fmt.Errorf(
			"!!! FATAL: no run command specified — "+
				"set 'run' in bindboss.toml or pass --run=\"cmd\"")
	}

	switch cfg.ExecMode {
	case "", "exec", "fork":
		// GRUG: empty string treated as "exec" (default). fine.
	default:
		return cfg, fmt.Errorf(
			"!!! FATAL: invalid exec_mode %q — must be \"exec\" or \"fork\"", cfg.ExecMode)
	}

	// GRUG: update URL set but persist not enabled = pointless. auto-fix it.
	// without persist, every run extracts from embedded payload and update
	// check can never take effect. warn loudly so user knows.
	if cfg.Update.URL != "" && !cfg.Extract.Persist {
		fmt.Fprintf(os.Stderr,
			"[bindboss] warning: --update requires --persist — auto-enabling persist mode\n")
		cfg.Extract.Persist = true
	}

	return cfg, nil
}