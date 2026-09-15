// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailscaled_test

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/k8s-operator/reconciler/tailscaled"
)

func TestPrefsFromStateSecret(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		data       map[string][]byte
		wantOK     bool
		wantErr    bool
		wantNodeID string
		wantLogin  string
		wantSvcs   []string
	}{
		"populated": {
			data: map[string][]byte{
				"_current-profile": []byte("profile-abc"),
				"profile-abc":      []byte(`{"Config":{"NodeID":"node-foo","UserProfile":{"LoginName":"foo.example.ts.net"}},"AdvertiseServices":["svc:bar"]}`),
			},
			wantOK:     true,
			wantNodeID: "node-foo",
			wantLogin:  "foo.example.ts.net",
			wantSvcs:   []string{"svc:bar"},
		},
		"no-current-profile": {
			data: map[string][]byte{
				"profile-abc": []byte(`{"Config":{"NodeID":"node-foo"}}`),
			},
		},
		"current-profile-points-at-missing-profile": {
			data: map[string][]byte{
				"_current-profile": []byte("profile-abc"),
			},
		},
		// The device hasn't finished authenticating, so there's no node ID yet.
		"no-node-id": {
			data: map[string][]byte{
				"_current-profile": []byte("profile-abc"),
				"profile-abc":      []byte(`{"Config":{"UserProfile":{"LoginName":"foo.example.ts.net"}}}`),
			},
			wantLogin: "foo.example.ts.net",
		},
		"empty": {},
		"malformed-profile": {
			data: map[string][]byte{
				"_current-profile": []byte("profile-abc"),
				"profile-abc":      []byte(`not json`),
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "tailscale"},
				Data:       tc.data,
			}

			prefs, ok, err := tailscaled.PrefsFromStateSecret(secret)
			switch {
			case tc.wantErr && err == nil:
				t.Fatal("expected an error, got nil")
			case !tc.wantErr && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr:
				return
			}

			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got := string(prefs.Config.NodeID); got != tc.wantNodeID {
				t.Errorf("NodeID = %q, want %q", got, tc.wantNodeID)
			}
			if got := prefs.Config.UserProfile.LoginName; got != tc.wantLogin {
				t.Errorf("LoginName = %q, want %q", got, tc.wantLogin)
			}
			if got, want := len(prefs.AdvertiseServices), len(tc.wantSvcs); got != want {
				t.Fatalf("len(AdvertiseServices) = %d, want %d", got, want)
			}
			for i, svc := range tc.wantSvcs {
				if prefs.AdvertiseServices[i] != svc {
					t.Errorf("AdvertiseServices[%d] = %q, want %q", i, prefs.AdvertiseServices[i], svc)
				}
			}
		})
	}
}
