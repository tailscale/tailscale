// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package nodekey

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/kube/kubetypes"
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
