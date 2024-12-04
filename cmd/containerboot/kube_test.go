// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/kube/kubeapi"
	"tailscale.com/kube/kubeclient"
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
