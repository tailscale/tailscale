// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubestore

import (
	"context"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
)

func TestUpdateStateSecret(t *testing.T) {
	tests := []struct {
		name       string
		initial    map[string][]byte
		updates    map[string][]byte
		wantData   map[string][]byte
		allowPatch bool
	}{
		{
			name: "basic_update",
			initial: map[string][]byte{
				"existing": []byte("old"),
			},
			updates: map[string][]byte{
				"foo": []byte("bar"),
			},
			wantData: map[string][]byte{
				"existing": []byte("old"),
				"foo":      []byte("bar"),
			},
			allowPatch: true,
		},
		{
			name: "update_existing",
			initial: map[string][]byte{
				"foo": []byte("old"),
			},
			updates: map[string][]byte{
				"foo": []byte("new"),
			},
			wantData: map[string][]byte{
				"foo": []byte("new"),
			},
			allowPatch: true,
		},
		{
			name: "multiple_updates",
			initial: map[string][]byte{
				"keep": []byte("keep"),
			},
			updates: map[string][]byte{
				"foo": []byte("bar"),
				"baz": []byte("qux"),
			},
			wantData: map[string][]byte{
				"keep": []byte("keep"),
				"foo":  []byte("bar"),
				"baz":  []byte("qux"),
			},
			allowPatch: true,
		},
		{
			name: "create_new_secret",
			updates: map[string][]byte{
				"foo": []byte("bar"),
			},
			wantData: map[string][]byte{
				"foo": []byte("bar"),
			},
			allowPatch: true,
		},
		{
			name: "patch_denied",
			initial: map[string][]byte{
				"foo": []byte("old"),
			},
			updates: map[string][]byte{
				"foo": []byte("new"),
			},
			wantData: map[string][]byte{
				"foo": []byte("new"),
			},
			allowPatch: false,
		},
		{
			name: "sanitize_keys",
			initial: map[string][]byte{
				"clean-key": []byte("old"),
			},
			updates: map[string][]byte{
				"dirty@key": []byte("new"),
				"also/bad":  []byte("value"),
				"good.key":  []byte("keep"),
			},
			wantData: map[string][]byte{
				"clean-key": []byte("old"),
				"dirty_key": []byte("new"),
				"also_bad":  []byte("value"),
				"good.key":  []byte("keep"),
			},
			allowPatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := tt.initial // track current state
			client := &kubeclient.FakeClient{
				GetSecretImpl: func(ctx context.Context, name string) (*kubeapi.Secret, error) {
					if secret == nil {
						return nil, &kubeapi.Status{Code: 404}
					}
					return &kubeapi.Secret{Data: secret}, nil
				},
				CheckSecretPermissionsImpl: func(ctx context.Context, name string) (bool, bool, error) {
					return tt.allowPatch, true, nil
				},
				CreateSecretImpl: func(ctx context.Context, s *kubeapi.Secret) error {
					secret = s.Data
					return nil
				},
				UpdateSecretImpl: func(ctx context.Context, s *kubeapi.Secret) error {
					secret = s.Data
					return nil
				},
				JSONPatchResourceImpl: func(ctx context.Context, name, resourceType string, patches []kubeclient.JSONPatch) error {
					if !tt.allowPatch {
						return &kubeapi.Status{Reason: "Forbidden"}
					}
					if secret == nil {
						secret = make(map[string][]byte)
					}
					for _, p := range patches {
						if p.Op == "add" && p.Path == "/data" {
							secret = p.Value.(map[string][]byte)
						} else if p.Op == "add" && strings.HasPrefix(p.Path, "/data/") {
							key := strings.TrimPrefix(p.Path, "/data/")
							secret[key] = p.Value.([]byte)
						}
					}
					return nil
				},
			}

			s := &Store{
				client:     client,
				canPatch:   tt.allowPatch,
				secretName: "test-secret",
				memory:     mem.Store{},
			}

			err := s.updateStateSecret(tt.updates)
			if err != nil {
				t.Errorf("updateStateSecret() error = %v", err)
				return
			}

			// Verify secret data
			if diff := cmp.Diff(secret, tt.wantData); diff != "" {
				t.Errorf("secret data mismatch (-got +want):\n%s", diff)
			}

			// Verify memory store was updated
			for k, v := range tt.updates {
				got, err := s.memory.ReadState(ipn.StateKey(k))
				if err != nil {
					t.Errorf("reading from memory store: %v", err)
					continue
				}
				if !cmp.Equal(got, v) {
					t.Errorf("memory store key %q = %v, want %v", k, got, v)
				}
			}
		})
	}
}
