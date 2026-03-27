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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/util/clientmetric"
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

	reconciler.SetFinalizer(object, reconciler.Finalizer)

	if !slices.Contains(object.Finalizers, reconciler.Finalizer) {
		t.Fatalf("object does not have finalizer %q: %v", reconciler.Finalizer, object.Finalizers)
	}

	reconciler.RemoveFinalizer(object, reconciler.Finalizer)

	if slices.Contains(object.Finalizers, reconciler.Finalizer) {
		t.Fatalf("object still has finalizer %q: %v", reconciler.Finalizer, object.Finalizers)
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

func TestResourceTracker(t *testing.T) {
	t.Parallel()

	gauge := clientmetric.NewGauge("k8s_reconciler_resource_tracker_test")
	tracker := reconciler.NewResourceTracker(gauge)

	if got := tracker.Len(); got != 0 {
		t.Fatalf("initial Len = %d, want 0", got)
	}
	if got := gauge.Value(); got != 0 {
		t.Fatalf("initial gauge = %d, want 0", got)
	}

	tracker.Add("uid-a")
	tracker.Add("uid-a") // duplicate is a no-op
	tracker.Add("uid-b")
	if got := tracker.Len(); got != 2 {
		t.Fatalf("Len after two distinct adds = %d, want 2", got)
	}
	if got := gauge.Value(); got != 2 {
		t.Fatalf("gauge after two distinct adds = %d, want 2", got)
	}

	tracker.Remove("uid-a")
	if got := tracker.Len(); got != 1 {
		t.Fatalf("Len after remove = %d, want 1", got)
	}
	if got := gauge.Value(); got != 1 {
		t.Fatalf("gauge after remove = %d, want 1", got)
	}

	// Remove of an unknown uid is a no-op.
	tracker.Remove("uid-missing")
	if got := tracker.Len(); got != 1 {
		t.Fatalf("Len after no-op remove = %d, want 1", got)
	}
}

func TestEnsureAndClearFinalizer(t *testing.T) {
	t.Parallel()

	newClient := func(obj client.Object) client.Client {
		scheme := runtime.NewScheme()
		if err := corev1.AddToScheme(scheme); err != nil {
			t.Fatalf("failed to build scheme: %v", err)
		}
		return fake.NewClientBuilder().WithScheme(scheme).WithObjects(obj).Build()
	}

	t.Run("ensure-adds-and-is-idempotent", func(t *testing.T) {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "ns"}}
		cl := newClient(secret)

		key := client.ObjectKeyFromObject(secret)
		if err := cl.Get(t.Context(), key, secret); err != nil {
			t.Fatalf("Get after seed: %v", err)
		}
		if err := reconciler.EnsureFinalizer(t.Context(), cl, secret, reconciler.Finalizer); err != nil {
			t.Fatalf("EnsureFinalizer: %v", err)
		}

		got := &corev1.Secret{}
		if err := cl.Get(t.Context(), key, got); err != nil {
			t.Fatalf("Get after ensure: %v", err)
		}
		if !slices.Contains(got.Finalizers, reconciler.Finalizer) {
			t.Fatalf("finalizer not set: %v", got.Finalizers)
		}
		firstRV := got.ResourceVersion

		// Second call must be a no-op — same ResourceVersion, no Update round-trip.
		if err := reconciler.EnsureFinalizer(t.Context(), cl, got, reconciler.Finalizer); err != nil {
			t.Fatalf("EnsureFinalizer (2nd): %v", err)
		}
		if err := cl.Get(t.Context(), key, got); err != nil {
			t.Fatalf("Get after 2nd ensure: %v", err)
		}
		if got.ResourceVersion != firstRV {
			t.Errorf("ResourceVersion changed on idempotent EnsureFinalizer: %q -> %q", firstRV, got.ResourceVersion)
		}
	})

	t.Run("clear-removes-and-is-idempotent", func(t *testing.T) {
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "ns", Finalizers: []string{reconciler.Finalizer}},
		}
		cl := newClient(secret)

		key := client.ObjectKeyFromObject(secret)
		if err := cl.Get(t.Context(), key, secret); err != nil {
			t.Fatalf("Get after seed: %v", err)
		}
		if err := reconciler.ClearFinalizer(t.Context(), cl, secret, reconciler.Finalizer); err != nil {
			t.Fatalf("ClearFinalizer: %v", err)
		}

		got := &corev1.Secret{}
		if err := cl.Get(t.Context(), key, got); err != nil {
			t.Fatalf("Get after clear: %v", err)
		}
		if slices.Contains(got.Finalizers, reconciler.Finalizer) {
			t.Fatalf("finalizer still present: %v", got.Finalizers)
		}
		firstRV := got.ResourceVersion

		// Idempotent — nothing left to remove, so no Update round-trip.
		if err := reconciler.ClearFinalizer(t.Context(), cl, got, reconciler.Finalizer); err != nil {
			t.Fatalf("ClearFinalizer (2nd): %v", err)
		}
		if err := cl.Get(t.Context(), key, got); err != nil {
			t.Fatalf("Get after 2nd clear: %v", err)
		}
		if got.ResourceVersion != firstRV {
			t.Errorf("ResourceVersion changed on idempotent ClearFinalizer: %q -> %q", firstRV, got.ResourceVersion)
		}
	})
}
