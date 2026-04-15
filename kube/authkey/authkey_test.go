// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package authkey

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
)

func TestSetReissueAuthKey(t *testing.T) {
	var patched map[string][]byte
	kc := &kubeclient.FakeClient{
		StrategicMergePatchSecretImpl: func(ctx context.Context, name string, secret *kubeapi.Secret, _ string) error {
			patched = secret.Data
			return nil
		},
	}

	err := SetReissueAuthKey(context.Background(), kc, "test-secret", "old-auth-key", TailscaleContainerFieldManager)
	if err != nil {
		t.Fatalf("SetReissueAuthKey() error = %v", err)
	}

	want := map[string][]byte{
		kubetypes.KeyReissueAuthkey: []byte("old-auth-key"),
	}
	if diff := cmp.Diff(want, patched); diff != "" {
		t.Errorf("SetReissueAuthKey() mismatch (-want +got):\n%s", diff)
	}
}

func TestClearReissueAuthKey(t *testing.T) {
	var patched map[string][]byte
	kc := &kubeclient.FakeClient{
		GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
			return &kubeapi.Secret{
				Data: map[string][]byte{
					"_current-profile": []byte("profile-abc1"),
					"profile-abc1":     []byte("some-profile-data"),
					"_machinekey":      []byte("machine-key-data"),
				},
			}, nil
		},
		StrategicMergePatchSecretImpl: func(ctx context.Context, name string, secret *kubeapi.Secret, _ string) error {
			patched = secret.Data
			return nil
		},
	}

	err := ClearReissueAuthKey(context.Background(), kc, "test-secret", TailscaleContainerFieldManager)
	if err != nil {
		t.Fatalf("ClearReissueAuthKey() error = %v", err)
	}

	want := map[string][]byte{
		kubetypes.KeyReissueAuthkey:        nil,
		kubetypes.KeyDeviceID:              nil,
		kubetypes.KeyDeviceFQDN:            nil,
		kubetypes.KeyDeviceIPs:             nil,
		string(ipn.MachineKeyStateKey):     nil,
		string(ipn.CurrentProfileStateKey): nil,
		string(ipn.KnownProfilesStateKey):  nil,
		"profile-abc1":                     nil,
	}
	if diff := cmp.Diff(want, patched); diff != "" {
		t.Errorf("ClearReissueAuthKey() mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthKeyFromConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		configContent string
		want          string
	}{
		"valid_config_with_authkey": {
			configContent: `{"Version":"alpha0","AuthKey":"test-auth-key"}`,
			want:          "test-auth-key",
		},
		"valid_config_without_authkey": {
			configContent: `{"Version":"alpha0"}`,
			want:          "",
		},
		"invalid_config": {
			configContent: `not valid json`,
			want:          "",
		},
		"empty_config": {
			configContent: ``,
			want:          "",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.json")

			if err := os.WriteFile(configPath, []byte(tc.configContent), 0600); err != nil {
				t.Fatalf("failed to write config file: %v", err)
			}

			got := AuthKeyFromConfig(configPath)
			if got != tc.want {
				t.Errorf("AuthKeyFromConfig() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("nonexistent_file", func(t *testing.T) {
		got := AuthKeyFromConfig("/nonexistent/path/config.json")
		if got != "" {
			t.Errorf("AuthKeyFromConfig() = %q, want empty string for nonexistent file", got)
		}
	})
}
