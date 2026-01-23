// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package reconciler_test

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/k8s-operator/reconciler"
)

func TestFinalizers(t *testing.T) {
	t.Parallel()

	object := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "test",
		},
		StringData: map[string]string{
			"hello": "world",
		},
	}

	reconciler.SetFinalizer(object)

	if !slices.Contains(object.Finalizers, reconciler.FinalizerName) {
		t.Fatalf("object does not have finalizer %q: %v", reconciler.FinalizerName, object.Finalizers)
	}

	reconciler.RemoveFinalizer(object)

	if slices.Contains(object.Finalizers, reconciler.FinalizerName) {
		t.Fatalf("object still has finalizer %q: %v", reconciler.FinalizerName, object.Finalizers)
	}
}
