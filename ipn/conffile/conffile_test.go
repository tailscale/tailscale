// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package conffile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tailscale.com/ipn"
)

func TestConfig_WantRunning(t *testing.T) {
	tests := []struct {
		name string
		c    *Config
		want bool
	}{
		{
			name: "nil_config",
			c:    nil,
			want: false,
		},
		{
			name: "enabled_true",
			c: &Config{
				Parsed: ipn.ConfigVAlpha{
					Enabled: ipn.BoolOrValue[bool]{Value: ipn.BoolTrue},
				},
			},
			want: true,
		},
		{
			name: "enabled_false",
			c: &Config{
				Parsed: ipn.ConfigVAlpha{
					Enabled: ipn.BoolOrValue[bool]{Value: ipn.BoolFalse},
				},
			},
			want: false,
		},
		{
			name: "enabled_unset",
			c: &Config{
				Parsed: ipn.ConfigVAlpha{},
			},
			want: true, // default is to run
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.c.WantRunning()
			if got != tt.want {
				t.Errorf("WantRunning() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoad_Success(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantVer string
	}{
		{
			name: "basic_alpha0",
			content: `{
				"version": "alpha0"
			}`,
			wantVer: "alpha0",
		},
		{
			name: "alpha0_with_enabled",
			content: `{
				"version": "alpha0",
				"enabled": true
			}`,
			wantVer: "alpha0",
		},
		{
			name: "hujson_with_comments",
			content: `{
				// This is a comment
				"version": "alpha0", // version field
				"enabled": true
			}`,
			wantVer: "alpha0",
		},
		{
			name: "hujson_trailing_commas",
			content: `{
				"version": "alpha0",
				"enabled": true,
			}`,
			wantVer: "alpha0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "config.json")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			c, err := Load(path)
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}

			if c == nil {
				t.Fatal("Load() returned nil config")
			}
			if c.Path != path {
				t.Errorf("Path = %q, want %q", c.Path, path)
			}
			if c.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", c.Version, tt.wantVer)
			}
			if len(c.Raw) == 0 {
				t.Error("Raw is empty")
			}
			if len(c.Std) == 0 {
				t.Error("Std is empty")
			}

			// Verify Std is valid JSON
			var v map[string]any
			if err := json.Unmarshal(c.Std, &v); err != nil {
				t.Errorf("Std is not valid JSON: %v", err)
			}
		})
	}
}

func TestLoad_Errors(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantErrHave string // substring that should be in error
	}{
		{
			name:        "invalid_json",
			content:     `{invalid json}`,
			wantErrHave: "error parsing",
		},
		{
			name:        "no_version",
			content:     `{"enabled": true}`,
			wantErrHave: "no \"version\" field",
		},
		{
			name:        "empty_version",
			content:     `{"version": ""}`,
			wantErrHave: "no \"version\" field",
		},
		{
			name:        "unsupported_version",
			content:     `{"version": "beta1"}`,
			wantErrHave: "unsupported \"version\"",
		},
		{
			name:        "unsupported_version_v1",
			content:     `{"version": "v1"}`,
			wantErrHave: "unsupported \"version\"",
		},
		{
			name: "unknown_field",
			content: `{
				"version": "alpha0",
				"unknownField": "value"
			}`,
			wantErrHave: "unknown field",
		},
		{
			name: "trailing_data",
			content: `{
				"version": "alpha0"
			}
			{
				"extra": "object"
			}`,
			wantErrHave: "trailing data",
		},
		{
			name:        "empty_file",
			content:     ``,
			wantErrHave: "error parsing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			path := filepath.Join(tmpDir, "config.json")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			c, err := Load(path)
			if err == nil {
				t.Errorf("Load() succeeded, want error containing %q", tt.wantErrHave)
			} else if !strings.Contains(err.Error(), tt.wantErrHave) {
				t.Errorf("Load() error = %q, want substring %q", err.Error(), tt.wantErrHave)
			}
			if c != nil {
				t.Errorf("Load() returned non-nil config on error")
			}
		})
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.json")
	if err == nil {
		t.Error("Load() with nonexistent file succeeded, want error")
	}
	if !os.IsNotExist(err) {
		t.Errorf("Load() error type: got %T, want os.PathError or similar", err)
	}
}

func TestLoad_VMUserDataPath(t *testing.T) {
	// This will fail unless we're running on an EC2 instance
	// Just verify it handles the special path
	_, err := Load(VMUserDataPath)
	// We expect an error since we're not on EC2
	// but we want to make sure it tries the right code path
	if err == nil {
		t.Skip("unexpectedly succeeded loading VM user data (are we on EC2?)")
	}

	// Error should be related to metadata service, not file I/O
	errStr := err.Error()
	if strings.Contains(errStr, "no such file") {
		t.Errorf("Load(VMUserDataPath) tried to read file instead of metadata service")
	}
}

func TestVMUserDataPath_Constant(t *testing.T) {
	if VMUserDataPath != "vm:user-data" {
		t.Errorf("VMUserDataPath = %q, want %q", VMUserDataPath, "vm:user-data")
	}
}

func TestLoad_PreservesRawBytes(t *testing.T) {
	content := `{
		// Comment
		"version": "alpha0",
		"enabled": true,
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Raw should contain the original HuJSON with comments
	if !strings.Contains(string(c.Raw), "// Comment") {
		t.Error("Raw doesn't preserve comments")
	}

	// Std should be valid JSON without comments
	if strings.Contains(string(c.Std), "//") {
		t.Error("Std contains comments (should be standardized JSON)")
	}
}

func TestLoad_ComplexConfig(t *testing.T) {
	content := `{
		"version": "alpha0",
		"enabled": true,
		"server": "https://login.tailscale.com",
		"hostname": "test-host",
		"authKey": "tskey-test-key"
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if c.Parsed.ServerURL != "https://login.tailscale.com" {
		t.Errorf("ServerURL = %q, want %q", c.Parsed.ServerURL, "https://login.tailscale.com")
	}
	if c.Parsed.Hostname != "test-host" {
		t.Errorf("Hostname = %q, want %q", c.Parsed.Hostname, "test-host")
	}
	if c.Parsed.AuthKey != "tskey-test-key" {
		t.Errorf("AuthKey = %q, want %q", c.Parsed.AuthKey, "tskey-test-key")
	}
}

func TestLoad_EmptyConfig(t *testing.T) {
	content := `{"version": "alpha0"}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Empty config should still be valid and want to run
	if !c.WantRunning() {
		t.Error("WantRunning() = false, want true for empty config")
	}
}

func TestLoad_PermissionCheck(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}

	content := `{"version": "alpha0"}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0000); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Error("Load() succeeded on unreadable file, want error")
	}
}

// Test concurrent loads
func TestLoad_Concurrent(t *testing.T) {
	content := `{"version": "alpha0", "enabled": true}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// Load the same file concurrently
	done := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := Load(path)
			done <- err
		}()
	}

	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent Load() failed: %v", err)
		}
	}
}

// Benchmark config loading
func BenchmarkLoad(b *testing.B) {
	content := `{
		"version": "alpha0",
		"enabled": true,
		"server": "https://login.tailscale.com",
		"hostname": "bench-host"
	}`

	tmpDir := b.TempDir()
	path := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		b.Fatalf("failed to write test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Load(path)
		if err != nil {
			b.Fatalf("Load() failed: %v", err)
		}
	}
}
