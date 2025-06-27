// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/types/ptr"
)

// Test that the config file can be at the root of the object, or in a versioned sub-object.
// or {"version": "v1beta1", "a-beta-config": "a-beta-value", "v1alpha1": {"authKey": "abc123"}}
func TestVersionedConfig(t *testing.T) {
	testCases := map[string]struct {
		inputConfig    string
		expectedConfig ConfigV1Alpha1
		expectedError  string
	}{
		"root_config_v1alpha1": {
			inputConfig:    `{"version": "v1alpha1", "authKey": "abc123"}`,
			expectedConfig: ConfigV1Alpha1{AuthKey: ptr.To("abc123")},
		},
		"backwards_compat_v1alpha1_config": {
			// Client doesn't know about v1beta1, so it should read in v1alpha1.
			inputConfig:    `{"version": "v1beta1", "beta-key": "beta-value", "authKey": "def456", "v1alpha1": {"authKey": "abc123"}}`,
			expectedConfig: ConfigV1Alpha1{AuthKey: ptr.To("abc123")},
		},
		"unknown_key_allowed": {
			// Adding new keys to the config doesn't require a version bump.
			inputConfig:    `{"version": "v1alpha1", "unknown-key": "unknown-value", "authKey": "abc123"}`,
			expectedConfig: ConfigV1Alpha1{AuthKey: ptr.To("abc123")},
		},
		"version_only_no_authkey": {
			inputConfig:    `{"version": "v1alpha1"}`,
			expectedConfig: ConfigV1Alpha1{},
		},
		"both_config_v1alpha1": {
			inputConfig:   `{"version": "v1alpha1", "authKey": "abc123", "v1alpha1": {"authKey": "def456"}}`,
			expectedError: "both root and v1alpha1 config provided",
		},
		"empty_config": {
			inputConfig:   `{}`,
			expectedError: `no "version" field provided`,
		},
		"v1beta1_without_backwards_compat": {
			inputConfig:   `{"version": "v1beta1", "beta-key": "beta-value", "authKey": "def456"}`,
			expectedError: `unsupported "version" value "v1beta1"; want "v1alpha1"`,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, []byte(tc.inputConfig), 0644); err != nil {
				t.Fatalf("failed to write config file: %v", err)
			}
			cfg, err := Load(path)
			switch {
			case tc.expectedError == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.expectedError != "":
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.expectedError)
				} else if !strings.Contains(err.Error(), tc.expectedError) {
					t.Fatalf("expected error %q, got %q", tc.expectedError, err.Error())
				}
				return
			}
			if cfg.Version != "v1alpha1" {
				t.Fatalf("expected version %q, got %q", "v1alpha1", cfg.Version)
			}
			// Diff actual vs expected config.
			if diff := cmp.Diff(cfg.Parsed, tc.expectedConfig); diff != "" {
				t.Fatalf("Unexpected parsed config (-got +want):\n%s", diff)
			}
		})
	}
}
