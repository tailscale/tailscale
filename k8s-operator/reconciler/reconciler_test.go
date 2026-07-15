// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package reconciler_test

import (
	"maps"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

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

func TestLabels(t *testing.T) {
	t.Parallel()

	t.Run("cluster-scoped-parent", func(t *testing.T) {
		got := reconciler.Labels("peerrelay", "test", "")
		want := map[string]string{
			"tailscale.com/managed":              "true",
			"tailscale.com/parent-resource-type": "peerrelay",
			"tailscale.com/parent-resource":      "test",
		}
		if !maps.Equal(got, want) {
			t.Errorf("expected %v, got %v", want, got)
		}
	})

	t.Run("namespaced-parent", func(t *testing.T) {
		got := reconciler.Labels("connector", "test", "kube-system")
		want := map[string]string{
			"tailscale.com/managed":              "true",
			"tailscale.com/parent-resource-type": "connector",
			"tailscale.com/parent-resource":      "test",
			"tailscale.com/parent-resource-ns":   "kube-system",
		}
		if !maps.Equal(got, want) {
			t.Errorf("expected %v, got %v", want, got)
		}
	})
}

func TestEnqueueForChild(t *testing.T) {
	t.Parallel()

	enqueue := reconciler.EnqueueForChild("peerrelay")

	tests := []struct {
		name   string
		labels map[string]string
		want   []ctrlreconcile.Request
	}{
		{
			name: "matching-cluster-scoped",
			labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource-type": "peerrelay",
				"tailscale.com/parent-resource":      "test",
			},
			want: []ctrlreconcile.Request{{NamespacedName: types.NamespacedName{Name: "test"}}},
		},
		{
			name: "matching-namespaced",
			labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource-type": "peerrelay",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   "kube-system",
			},
			want: []ctrlreconcile.Request{{NamespacedName: types.NamespacedName{Name: "test", Namespace: "kube-system"}}},
		},
		{
			name: "not-managed",
			labels: map[string]string{
				"tailscale.com/parent-resource-type": "peerrelay",
				"tailscale.com/parent-resource":      "test",
			},
		},
		{
			name: "wrong-parent-type",
			labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource-type": "proxygroup",
				"tailscale.com/parent-resource":      "test",
			},
		},
		{
			name: "missing-parent-name",
			labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource-type": "peerrelay",
			},
		},
		{
			name: "no-labels",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			obj := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Labels: tc.labels}}
			got := enqueue(t.Context(), obj)
			if !slices.Equal(got, tc.want) {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
