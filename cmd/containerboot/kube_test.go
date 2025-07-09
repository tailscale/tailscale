// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/ingressservices"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
)

func TestSetupKube(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *settings
		wantErr bool
		wantCfg *settings
		kc      *kubeClient
	}{
		{
			name: "TS_AUTHKEY set, state Secret exists",
			cfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, false, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return nil, nil
				},
			}},
			wantCfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
		},
		{
			name: "TS_AUTHKEY set, state Secret does not exist, we have permissions to create it",
			cfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, true, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return nil, &kubeapi.Status{Code: 404}
				},
			}},
			wantCfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
		},
		{
			name: "TS_AUTHKEY set, state Secret does not exist, we do not have permissions to create it",
			cfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, false, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return nil, &kubeapi.Status{Code: 404}
				},
			}},
			wantCfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			wantErr: true,
		},
		{
			name: "TS_AUTHKEY set, we encounter a non-404 error when trying to retrieve the state Secret",
			cfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, false, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return nil, &kubeapi.Status{Code: 403}
				},
			}},
			wantCfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			wantErr: true,
		},
		{
			name: "TS_AUTHKEY set, we encounter a non-404 error when trying to check Secret permissions",
			cfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			wantCfg: &settings{
				AuthKey:    "foo",
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, false, errors.New("broken")
				},
			}},
			wantErr: true,
		},
		{
			// Interactive login using URL in Pod logs
			name: "TS_AUTHKEY not set, state Secret does not exist, we have permissions to create it",
			cfg: &settings{
				KubeSecret: "foo",
			},
			wantCfg: &settings{
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, true, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return nil, &kubeapi.Status{Code: 404}
				},
			}},
		},
		{
			// Interactive login using URL in Pod logs
			name: "TS_AUTHKEY not set, state Secret exists, but does not contain auth key",
			cfg: &settings{
				KubeSecret: "foo",
			},
			wantCfg: &settings{
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, false, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return &kubeapi.Secret{}, nil
				},
			}},
		},
		{
			name: "TS_AUTHKEY not set, state Secret contains auth key, we do not have RBAC to patch it",
			cfg: &settings{
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return false, false, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return &kubeapi.Secret{Data: map[string][]byte{"authkey": []byte("foo")}}, nil
				},
			}},
			wantCfg: &settings{
				KubeSecret: "foo",
			},
			wantErr: true,
		},
		{
			name: "TS_AUTHKEY not set, state Secret contains auth key, we have RBAC to patch it",
			cfg: &settings{
				KubeSecret: "foo",
			},
			kc: &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				CheckSecretPermissionsImpl: func(context.Context, string) (bool, bool, error) {
					return true, false, nil
				},
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return &kubeapi.Secret{Data: map[string][]byte{"authkey": []byte("foo")}}, nil
				},
			}},
			wantCfg: &settings{
				KubeSecret:         "foo",
				AuthKey:            "foo",
				KubernetesCanPatch: true,
			},
		},
	}

	for _, tt := range tests {
		kc := tt.kc
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.setupKube(context.Background(), kc); (err != nil) != tt.wantErr {
				t.Errorf("settings.setupKube() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(*tt.cfg, *tt.wantCfg); diff != "" {
				t.Errorf("unexpected contents of settings after running settings.setupKube()\n(-got +want):\n%s", diff)
			}
		})
	}
}

func TestWaitForConsistentState(t *testing.T) {
	data := map[string][]byte{
		// Missing _current-profile.
		string(ipn.KnownProfilesStateKey): []byte(""),
		string(ipn.MachineKeyStateKey):    []byte(""),
		"profile-foo":                     []byte(""),
	}
	kc := &kubeClient{
		Client: &kubeclient.FakeClient{
			GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
				return &kubeapi.Secret{
					Data: data,
				}, nil
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := kc.waitForConsistentState(ctx); err != context.DeadlineExceeded {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data[string(ipn.CurrentProfileStateKey)] = []byte("")
	if err := kc.waitForConsistentState(ctx); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestResetContainerbootState(t *testing.T) {
	capver := fmt.Appendf(nil, "%d", tailcfg.CurrentCapabilityVersion)
	for name, tc := range map[string]struct {
		podUID   string
		authkey  string
		initial  map[string][]byte
		expected map[string][]byte
	}{
		"empty_initial": {
			podUID:  "1234",
			authkey: "new-authkey",
			initial: map[string][]byte{},
			expected: map[string][]byte{
				kubetypes.KeyCapVer: capver,
				kubetypes.KeyPodUID: []byte("1234"),
				// Cleared keys.
				kubetypes.KeyDeviceID:            nil,
				kubetypes.KeyDeviceFQDN:          nil,
				kubetypes.KeyDeviceIPs:           nil,
				kubetypes.KeyHTTPSEndpoint:       nil,
				egressservices.KeyEgressServices: nil,
				ingressservices.IngressConfigKey: nil,
			},
		},
		"empty_initial_no_pod_uid": {
			initial: map[string][]byte{},
			expected: map[string][]byte{
				kubetypes.KeyCapVer: capver,
				// Cleared keys.
				kubetypes.KeyDeviceID:            nil,
				kubetypes.KeyDeviceFQDN:          nil,
				kubetypes.KeyDeviceIPs:           nil,
				kubetypes.KeyHTTPSEndpoint:       nil,
				egressservices.KeyEgressServices: nil,
				ingressservices.IngressConfigKey: nil,
			},
		},
		"only_relevant_keys_updated": {
			podUID:  "1234",
			authkey: "new-authkey",
			initial: map[string][]byte{
				kubetypes.KeyCapVer:              []byte("1"),
				kubetypes.KeyPodUID:              []byte("5678"),
				kubetypes.KeyDeviceID:            []byte("device-id"),
				kubetypes.KeyDeviceFQDN:          []byte("device-fqdn"),
				kubetypes.KeyDeviceIPs:           []byte(`["192.0.2.1"]`),
				kubetypes.KeyHTTPSEndpoint:       []byte("https://example.com"),
				egressservices.KeyEgressServices: []byte("egress-services"),
				ingressservices.IngressConfigKey: []byte("ingress-config"),
				"_current-profile":               []byte("current-profile"),
				"_machinekey":                    []byte("machine-key"),
				"_profiles":                      []byte("profiles"),
				"_serve_e0ce":                    []byte("serve-e0ce"),
				"profile-e0ce":                   []byte("profile-e0ce"),
			},
			expected: map[string][]byte{
				kubetypes.KeyCapVer: capver,
				kubetypes.KeyPodUID: []byte("1234"),
				// Cleared keys.
				kubetypes.KeyDeviceID:            nil,
				kubetypes.KeyDeviceFQDN:          nil,
				kubetypes.KeyDeviceIPs:           nil,
				kubetypes.KeyHTTPSEndpoint:       nil,
				egressservices.KeyEgressServices: nil,
				ingressservices.IngressConfigKey: nil,
				// Tailscaled keys not included in patch.
			},
		},
		"new_authkey_issued": {
			initial: map[string][]byte{
				kubetypes.KeyReissueAuthkey: []byte("old-authkey"),
			},
			authkey: "new-authkey",
			expected: map[string][]byte{
				kubetypes.KeyCapVer:         capver,
				kubetypes.KeyReissueAuthkey: nil,
				// Cleared keys.
				kubetypes.KeyDeviceID:            nil,
				kubetypes.KeyDeviceFQDN:          nil,
				kubetypes.KeyDeviceIPs:           nil,
				kubetypes.KeyHTTPSEndpoint:       nil,
				egressservices.KeyEgressServices: nil,
				ingressservices.IngressConfigKey: nil,
			},
		},
		"authkey_not_yet_updated": {
			initial: map[string][]byte{
				kubetypes.KeyReissueAuthkey: []byte("old-authkey"),
			},
			authkey: "old-authkey",
			expected: map[string][]byte{
				kubetypes.KeyCapVer: capver,
				// reissue_authkey not cleared.
				// Cleared keys.
				kubetypes.KeyDeviceID:            nil,
				kubetypes.KeyDeviceFQDN:          nil,
				kubetypes.KeyDeviceIPs:           nil,
				kubetypes.KeyHTTPSEndpoint:       nil,
				egressservices.KeyEgressServices: nil,
				ingressservices.IngressConfigKey: nil,
			},
		},
		"authkey_deleted_from_config": {
			initial: map[string][]byte{
				kubetypes.KeyReissueAuthkey: []byte("old-authkey"),
			},
			authkey: "",
			expected: map[string][]byte{
				kubetypes.KeyCapVer: capver,
				// reissue_authkey not cleared.
				// Cleared keys.
				kubetypes.KeyDeviceID:            nil,
				kubetypes.KeyDeviceFQDN:          nil,
				kubetypes.KeyDeviceIPs:           nil,
				kubetypes.KeyHTTPSEndpoint:       nil,
				egressservices.KeyEgressServices: nil,
				ingressservices.IngressConfigKey: nil,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var actual map[string][]byte
			kc := &kubeClient{stateSecret: "foo", Client: &kubeclient.FakeClient{
				GetSecretImpl: func(context.Context, string) (*kubeapi.Secret, error) {
					return &kubeapi.Secret{
						Data: tc.initial,
					}, nil
				},
				StrategicMergePatchSecretImpl: func(ctx context.Context, name string, secret *kubeapi.Secret, _ string) error {
					actual = secret.Data
					return nil
				},
			}}
			if err := kc.resetContainerbootState(context.Background(), tc.podUID, tc.authkey); err != nil {
				t.Fatalf("resetContainerbootState() error = %v", err)
			}
			if diff := cmp.Diff(actual, tc.expected); diff != "" {
				t.Errorf("Merge patch mismatch (-got +want):\n%s", diff)
			}
		})
	}
}
