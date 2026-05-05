// toml.go
// =============================================================================
// GRUG: grug need to write config back to toml. packer merges flags into
// toml, then writes merged toml into archive. stub reads it. one source of
// truth. simple.
//
// GRUG: BurntSushi/toml can encode but it wants a map. grug convert struct
// to map first, then encode. not pretty but works. BurntSushi v1 has
// toml.Marshal now but grug stick with what grug know.
//
// -----------------------------------------------------------------------------
// ACADEMIC FOOTER:
// ToTOML serializes a Config value to TOML bytes using an intermediate
// map[string]any representation. This avoids relying on struct tags for
// encoding (which BurntSushi/toml v0.x does not support for marshalling)
// and gives us full control over the output format and field ordering.
// =============================================================================

package config

import (
	"bytes"
	"fmt"

	"github.com/BurntSushi/toml"
)

// ToTOML serializes a Config to TOML bytes.
// GRUG: packer writes merged config into archive. stub reads it back.
// round-trip must be lossless or grug lose settings. test this.
func ToTOML(cfg Config) ([]byte, error) {
	// GRUG: build map by hand so field order is deterministic and grug
	// control exactly what gets written. no surprises from reflection.
	m := map[string]any{
		"name":      cfg.Name,
		"run":       cfg.Run,
		"exec_mode": cfg.ExecMode,
		"env":       cfg.Env,
	}

	// GRUG: needs array. only write if non-empty.
	if len(cfg.Needs) > 0 {
		needs := make([]map[string]string, len(cfg.Needs))
		for i, dep := range cfg.Needs {
			needs[i] = map[string]string{
				"name":    dep.Name,
				"check":   dep.Check,
				"url":     dep.URL,
				"message": dep.Message,
			}
		}
		m["needs"] = needs
	}

	// GRUG: extract section. always write it.
	m["extract"] = map[string]any{
		"persist": cfg.Extract.Persist,
		"cleanup": cfg.Extract.Cleanup,
		"dir":     cfg.Extract.Dir,
	}

	// GRUG: hooks section. only write if non-empty.
	if len(cfg.Hooks.PreRun) > 0 || len(cfg.Hooks.PostRun) > 0 {
		hooks := map[string]any{}
		if len(cfg.Hooks.PreRun) > 0 {
			hooks["pre_run"] = cfg.Hooks.PreRun
		}
		if len(cfg.Hooks.PostRun) > 0 {
			hooks["post_run"] = cfg.Hooks.PostRun
		}
		m["hooks"] = hooks
	}

	// GRUG: install section. only write if enabled.
	if cfg.Install.Enabled || cfg.Install.ConfigInline != "" || cfg.Install.ConfigFile != "" {
		m["install"] = map[string]any{
			"enabled":        cfg.Install.Enabled,
			"install_config": cfg.Install.ConfigInline,
			"install_file":   cfg.Install.ConfigFile,
		}
	}

	// GRUG: update section. only write if URL is set.
	if cfg.Update.URL != "" {
		update := map[string]any{
			"url": cfg.Update.URL,
		}
		if cfg.Update.Branch != "" {
			update["branch"] = cfg.Update.Branch
		}
		m["update"] = update
	}

	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(m); err != nil {
		return nil, fmt.Errorf("!!! FATAL: cannot encode config to TOML: %w", err)
	}

	return buf.Bytes(), nil
}