// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package tailnet

import (
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

func TestJWTFromSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tailnet-credentials",
			Namespace: "tailscale",
		},
		Data: map[string][]byte{jwtKey: []byte("initial-jwt")},
	}
	cl := fake.NewClientBuilder().WithScheme(tsapi.GlobalScheme).WithObjects(secret).Build()
	reconciler := &Reconciler{Client: cl}
	token := reconciler.jwtFromSecret(types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace})

	got, err := token()
	if err != nil {
		t.Fatal(err)
	}
	if got != "initial-jwt" {
		t.Fatalf("got JWT %q, want initial JWT", got)
	}

	secret.Data[jwtKey] = []byte("refreshed-jwt")
	if err := cl.Update(t.Context(), secret); err != nil {
		t.Fatal(err)
	}

	got, err = token()
	if err != nil {
		t.Fatal(err)
	}
	if got != "refreshed-jwt" {
		t.Fatalf("got JWT %q, want refreshed JWT", got)
	}
}

func TestTailnetsForSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tailnet-credentials",
			Namespace: "tailscale",
		},
	}
	tailnets := []tsapi.Tailnet{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "matching"},
			Spec: tsapi.TailnetSpec{
				Credentials: tsapi.TailnetCredentials{SecretName: secret.Name},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "other"},
			Spec: tsapi.TailnetSpec{
				Credentials: tsapi.TailnetCredentials{SecretName: "other-credentials"},
			},
		},
	}
	cl := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(&tailnets[0], &tailnets[1]).
		WithIndex(new(tsapi.Tailnet), indexTailnetCredentialSecret, indexCredentialSecret).
		Build()
	logger := zap.NewNop().Sugar()
	reconciler := &Reconciler{Client: cl, logger: logger, tailscaleNamespace: secret.Namespace}

	got := reconciler.tailnetsForSecret(t.Context(), secret)
	want := []reconcile.Request{{NamespacedName: types.NamespacedName{Name: "matching"}}}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("got reconcile requests %v, want %v", got, want)
	}

	secret.Namespace = "other"
	if got = reconciler.tailnetsForSecret(t.Context(), secret); got != nil {
		t.Fatalf("got reconcile requests %v for a Secret outside the operator namespace", got)
	}
}
