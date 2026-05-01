// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/health"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
)

func TestResetState(t *testing.T) {
	tests := []struct {
		name          string
		existingData  map[string][]byte
		podUID        string
		configAuthKey string
		wantPatched   map[string][]byte
	}{
		{
			name: "sets_capver_and_pod_uid",
			existingData: map[string][]byte{
				kubetypes.KeyDeviceID:   []byte("device-123"),
				kubetypes.KeyDeviceFQDN: []byte("node.tailnet"),
				kubetypes.KeyDeviceIPs:  []byte(`["100.64.0.1"]`),
			},
			podUID:        "pod-123",
			configAuthKey: "new-key",
			wantPatched: map[string][]byte{
				kubetypes.KeyPodUID: []byte("pod-123"),
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
				kubetypes.KeyPodUID:         []byte("pod-123"),
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
				kubetypes.KeyPodUID: []byte("pod-123"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

func TestNeedsAuthKeyReissue(t *testing.T) {
	loginWarnableCode := string(health.LoginStateWarnable.Code)

	tests := []struct {
		name         string
		backendState string
		health       []string
		want         bool
	}{
		{
			name:         "running_healthy",
			backendState: "Running",
			want:         false,
		},
		{
			name:         "needs_login",
			backendState: "NeedsLogin",
			want:         true,
		},
		{
			name:         "running_with_login_warning",
			backendState: "Running",
			health:       []string{"warning: " + loginWarnableCode + ": you are logged out"},
			want:         true,
		},
		{
			name:         "running_with_unrelated_warning",
			backendState: "Running",
			health:       []string{"dns-not-working"},
			want:         false,
		},
		{
			name:         "running_no_warnings",
			backendState: "Running",
			health:       nil,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := needsAuthKeyReissue(tt.backendState, tt.health)
			if got != tt.want {
				t.Errorf("needsAuthKeyReissue() = %v, want %v", got, tt.want)
			}
		})
	}
}
