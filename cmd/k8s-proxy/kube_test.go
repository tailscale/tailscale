// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
)

func TestExtractStateSecretName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      string
		wantError bool
	}{
		{
			name:  "valid_kube_path",
			input: "kube:tailscale-state",
			want:  "tailscale-state",
		},
		{
			name:  "valid_kube_path_with_namespace",
			input: "kube:tailscale-state-ns",
			want:  "tailscale-state-ns",
		},
		{
			name:      "non_kube_path",
			input:     "mem:",
			wantError: true,
		},
		{
			name:      "empty_secret_name",
			input:     "kube:",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractStateSecretName(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResetState(t *testing.T) {
	tests := []struct {
		name          string
		existingData  map[string][]byte
		podUID        string
		configAuthKey string
		wantPatched   map[string][]byte
	}{
		{
			name: "clears_device_state",
			existingData: map[string][]byte{
				kubetypes.KeyDeviceID:   []byte("device-123"),
				kubetypes.KeyDeviceFQDN: []byte("node.tailnet"),
				kubetypes.KeyDeviceIPs:  []byte(`["100.64.0.1"]`),
			},
			podUID:        "pod-123",
			configAuthKey: "new-key",
			wantPatched: map[string][]byte{
				kubetypes.KeyCapVer:     []byte("95"),
				kubetypes.KeyPodUID:     []byte("pod-123"),
				kubetypes.KeyDeviceID:   nil,
				kubetypes.KeyDeviceFQDN: nil,
				kubetypes.KeyDeviceIPs:  nil,
			},
		},
		{
			name: "clears_reissue_marker_when_actioned",
			existingData: map[string][]byte{
				kubetypes.KeyReissueAuthkey: []byte("old-key"),
			},
			podUID:        "pod-123",
			configAuthKey: "new-key",
			wantPatched: map[string][]byte{
				kubetypes.KeyCapVer:         []byte("95"),
				kubetypes.KeyPodUID:         []byte("pod-123"),
				kubetypes.KeyDeviceID:       nil,
				kubetypes.KeyDeviceFQDN:     nil,
				kubetypes.KeyDeviceIPs:      nil,
				kubetypes.KeyReissueAuthkey: nil,
			},
		},
		{
			name: "keeps_reissue_marker_when_not_actioned",
			existingData: map[string][]byte{
				kubetypes.KeyReissueAuthkey: []byte("old-key"),
			},
			podUID:        "pod-123",
			configAuthKey: "old-key",
			wantPatched: map[string][]byte{
				kubetypes.KeyCapVer:     []byte("95"),
				kubetypes.KeyPodUID:     []byte("pod-123"),
				kubetypes.KeyDeviceID:   nil,
				kubetypes.KeyDeviceFQDN: nil,
				kubetypes.KeyDeviceIPs:  nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Adjust expected cap ver to match actual current version.
			tt.wantPatched[kubetypes.KeyCapVer] = []byte{0}
			tt.wantPatched[kubetypes.KeyCapVer] = fmt.Appendf(nil, "%d", tailcfg.CurrentCapabilityVersion)

			var patched map[string][]byte
			kc := &kubeclient.FakeClient{
				GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
					return &kubeapi.Secret{Data: tt.existingData}, nil
				},
				StrategicMergePatchSecretImpl: func(ctx context.Context, name string, s *kubeapi.Secret, fm string) error {
					patched = s.Data
					return nil
				},
			}

			err := resetState(context.Background(), kc, "test-secret", tt.podUID, tt.configAuthKey)
			if err != nil {
				t.Fatalf("resetState() error = %v", err)
			}

			if diff := cmp.Diff(tt.wantPatched, patched); diff != "" {
				t.Errorf("resetState() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
