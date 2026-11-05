// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package reconciler_test

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"go.uber.org/zap"
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

func TestIsOptimisticLockError(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil": {},
		"conflict": {
			err:  errors.New("Operation cannot be fulfilled on secrets \"test\": the object has been modified; please apply your changes to the latest version and try again"),
			want: true,
		},
		"unrelated": {
			err: errors.New("secrets \"test\" not found"),
		},
		"wrapped-conflict": {
			err:  fmt.Errorf("failed to update Secret: %w", errors.New("the object has been modified; please apply your changes to the latest version and try again")),
			want: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := reconciler.IsOptimisticLockError(tc.err); got != tc.want {
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

func TestValidateService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		annotations map[string]string
		clusterIP   string
		want        []string
	}{
		{
			name: "valid-magicdns-name",
			annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.tail4567.ts.net",
			},
		},
		{
			name: "valid-magicdns-name-with-trailing-dot",
			annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.tail4567.ts.net.",
			},
		},
		{
			name: "invalid-magicdns-name",
			annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.tail4567",
			},
			want: []string{`invalid value of annotation tailscale.com/tailnet-fqdn: "foo.tail4567" does not appear to be a valid MagicDNS name`},
		},
		{
			name: "both-tailnet-targets",
			annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.tail4567.ts.net",
				reconciler.AnnotationTailnetTargetIP:   "100.64.0.1",
			},
			want: []string{"only one of annotations tailscale.com/tailnet-ip and tailscale.com/tailnet-fqdn can be set"},
		},
		{
			name: "invalid-tailnet-ip",
			annotations: map[string]string{
				reconciler.AnnotationTailnetTargetIP: "not-an-ip",
			},
			want: []string{`invalid value of annotation tailscale.com/tailnet-ip: "not-an-ip" could not be parsed as a valid IP Address, error: ParseAddr("not-an-ip"): unable to parse IP`},
		},
		{
			name:      "headless",
			clusterIP: "None",
			want:      []string{"headless Services are not supported."},
		},
		{
			name: "invalid-hostname",
			annotations: map[string]string{
				reconciler.AnnotationHostname: "foo.bar",
			},
			want: []string{`invalid Tailscale hostname specified "foo.bar": "foo.bar" is not a valid DNS label: contains invalid character '.'`},
		},
		{
			name: "invalid-tag",
			annotations: map[string]string{
				reconciler.AnnotationTags: "tag:ok,notatag",
			},
			want: []string{`invalid tag "notatag": tags must start with 'tag:'`},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "test",
					Namespace:   "default",
					Annotations: tc.annotations,
				},
				Spec: corev1.ServiceSpec{ClusterIP: tc.clusterIP},
			}
			got := reconciler.ValidateService(svc)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("ValidateService() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClusterDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// resolvConf is the content of the file that ClusterDomain parses. Empty means that the file does not exist.
		resolvConf string
		namespace  string
		want       string
	}{
		{
			name:       "success-custom-domain",
			resolvConf: "search foo.svc.department.org.io svc.department.org.io department.org.io\n",
			namespace:  "foo",
			want:       "department.org.io",
		},
		{
			name:       "success-default-domain",
			resolvConf: "search foo.svc.cluster.local. svc.cluster.local. cluster.local.\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		{
			name:       "only-two-search-domains",
			resolvConf: "search svc.department.org.io department.org.io\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		{
			name:       "first-search-domain-mismatch",
			resolvConf: "search foo.bar.department.org.io svc.department.org.io some.other.fqdn\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		{
			name:       "second-search-domain-mismatch",
			resolvConf: "search foo.svc.department.org.io foo.department.org.io some.other.fqdn\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		{
			name:       "third-search-domain-mismatch",
			resolvConf: "search foo.svc.department.org.io svc.department.org.io some.other.fqdn\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		{
			name:      "missing-resolv-conf",
			namespace: "foo",
			want:      "cluster.local",
		},
	}

	logger := zap.Must(zap.NewDevelopment()).Sugar()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "resolv.conf")
			if tc.resolvConf != "" {
				if err := os.WriteFile(path, []byte(tc.resolvConf), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := reconciler.ClusterDomain(tc.namespace, logger, reconciler.WithResolvConfPath(path)); got != tc.want {
				t.Errorf("ClusterDomain() = %q, want %q", got, tc.want)
			}
		})
	}
}
