// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nodekey

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/ipn"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/types/key"
	"tailscale.com/types/persist"
)

func TestManagedSecretHandler(t *testing.T) {
	const ns = "tailscale"
	tests := []struct {
		name      string
		namespace string
		labels    map[string]string
		wantQueue bool
	}{
		{
			// No secret type label, as on the state Secrets of standalone proxies.
			name:      "managed_secret_in_operator_namespace",
			namespace: ns,
			labels:    map[string]string{kubetypes.LabelManaged: "true"},
			wantQueue: true,
		},
		{
			name:      "managed_state_secret",
			namespace: ns,
			labels:    map[string]string{kubetypes.LabelManaged: "true", kubetypes.LabelSecretType: kubetypes.LabelSecretTypeState},
			wantQueue: true,
		},
		{
			name:      "managed_config_secret",
			namespace: ns,
			labels:    map[string]string{kubetypes.LabelManaged: "true", kubetypes.LabelSecretType: kubetypes.LabelSecretTypeConfig},
			wantQueue: false,
		},
		{
			name:      "managed_secret_in_other_namespace",
			namespace: "other",
			labels:    map[string]string{kubetypes.LabelManaged: "true"},
			wantQueue: false,
		},
		{
			name:      "unmanaged_secret_in_operator_namespace",
			namespace: ns,
			labels:    nil,
			wantQueue: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-secret",
					Namespace: tt.namespace,
					Labels:    tt.labels,
				},
			}

			reqs := managedSecretHandler(ns)(t.Context(), secret)
			if !tt.wantQueue {
				if len(reqs) != 0 {
					t.Fatalf("expected no requests, got %v", reqs)
				}
				return
			}

			want := reconcile.Request{}
			want.Name = secret.Name
			want.Namespace = secret.Namespace
			if len(reqs) != 1 || reqs[0] != want {
				t.Fatalf("expected [%v], got %v", want, reqs)
			}
		})
	}
}

func TestPredicateSigningInputsChanged(t *testing.T) {
	const profileKey = "profile-test"
	profile := func(nodeKey key.NodePrivate) []byte {
		b, err := json.Marshal(ipn.Prefs{Persist: &persist.Persist{PrivateNodeKey: nodeKey}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	nodeKey := key.NewNode()
	oldSecret := &corev1.Secret{
		Data: map[string][]byte{
			kubetypes.KeyDeviceID:              []byte("device-id"),
			kubetypes.KeyPodUID:                []byte("pod-uid"),
			string(ipn.CurrentProfileStateKey): []byte(profileKey),
			profileKey:                         profile(nodeKey),
		},
	}

	tests := []struct {
		name     string
		mutateFn func(*corev1.Secret)
		want     bool
	}{
		{
			name:     "unrelated_change",
			mutateFn: func(s *corev1.Secret) { s.Data[kubetypes.KeyDeviceIPs] = []byte(`["100.64.0.1"]`) },
			want:     false,
		},
		{
			name:     "device_id_changed",
			mutateFn: func(s *corev1.Secret) { s.Data[kubetypes.KeyDeviceID] = []byte("other-device-id") },
			want:     true,
		},
		{
			name:     "pod_uid_changed",
			mutateFn: func(s *corev1.Secret) { s.Data[kubetypes.KeyPodUID] = []byte("other-pod-uid") },
			want:     true,
		},
		{
			name:     "node_key_rotated",
			mutateFn: func(s *corev1.Secret) { s.Data[profileKey] = profile(key.NewNode()) },
			want:     true,
		},
		{
			name:     "malformed_profile",
			mutateFn: func(s *corev1.Secret) { s.Data[profileKey] = []byte("not-a-profile") },
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newSecret := oldSecret.DeepCopy()
			tt.mutateFn(newSecret)

			got := predicateSigningInputsChanged().Update(event.TypedUpdateEvent[*corev1.Secret]{
				ObjectOld: oldSecret,
				ObjectNew: newSecret,
			})
			if got != tt.want {
				t.Errorf("Update() = %v, want %v", got, tt.want)
			}
		})
	}
}
