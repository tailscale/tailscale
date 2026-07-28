// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conffile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLoadAbsentIsErrNoConfig verifies that an absent config source (here a
// missing file, the same read-phase seam the "vm:user-data" 404 goes through)
// is reported as ErrNoConfig, so callers using tailscaled's "optional:" prefix
// can boot unconfigured instead of failing.
func TestLoadAbsentIsErrNoConfig(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if !errors.Is(err, ErrNoConfig) {
		t.Fatalf("Load(missing) error = %v; want it to wrap ErrNoConfig", err)
	}
}

// TestLoadInvalidIsNotErrNoConfig verifies that a config that is present but
// invalid is NOT ErrNoConfig, so it stays fatal even in optional mode.
func TestLoadInvalidIsNotErrNoConfig(t *testing.T) {
	for name, data := range map[string]string{
		"malformed":       `{"Version": "alpha0"`, // truncated JSON
		"unknown-version": `{"Version": "bogus9"}`,
		"unknown-field":   `{"Version": "alpha0", "Bogus": true}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "bad.json")
			if err := os.WriteFile(p, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(p)
			if err == nil {
				t.Fatalf("Load(%q) succeeded; want an error", data)
			}
			if errors.Is(err, ErrNoConfig) {
				t.Fatalf("Load(%q) error = %v; want a parse error, not ErrNoConfig", data, err)
			}
		})
	}
}

func TestLoadValid(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.json")
	if err := os.WriteFile(p, []byte(`{"Version": "alpha0"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load(valid) error = %v; want nil", err)
	}
	if c.Version != "alpha0" {
		t.Fatalf("Version = %q; want alpha0", c.Version)
	}
}
