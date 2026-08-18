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
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrlreconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/tstest"
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

func TestClusterDomain(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// resolvConf is the file ClusterDomain parses. Empty means don't create the file at all, exercising the
		// unreadable-config path.
		resolvConf string
		namespace  string
		want       string
	}{
		"custom-domain": {
			resolvConf: "search foo.svc.department.org.io svc.department.org.io department.org.io\nnameserver 10.96.0.10\n",
			namespace:  "foo",
			want:       "department.org.io",
		},
		"default-domain": {
			resolvConf: "search foo.svc.cluster.local svc.cluster.local cluster.local\nnameserver 10.96.0.10\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		// Everything below should fall back to the default rather than error.
		"only-two-search-domains": {
			resolvConf: "search svc.department.org.io department.org.io\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		"first-search-domain-mismatch": {
			resolvConf: "search foo.bar.department.org.io svc.department.org.io some.other.fqdn\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		"second-search-domain-mismatch": {
			resolvConf: "search foo.svc.department.org.io foo.department.org.io some.other.fqdn\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		"third-search-domain-mismatch": {
			resolvConf: "search foo.svc.department.org.io svc.department.org.io some.other.fqdn\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		// The domain here is deliberately not cluster.local: if the namespace check were skipped, this config
		// would parse cleanly and yield department.org.io, so the expected fallback distinguishes the two.
		"namespace-mismatch": {
			resolvConf: "search bar.svc.department.org.io svc.department.org.io department.org.io\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		"no-search-domains": {
			resolvConf: "nameserver 10.96.0.10\n",
			namespace:  "foo",
			want:       "cluster.local",
		},
		"missing-file": {
			namespace: "foo",
			want:      "cluster.local",
		},
	}

	logger := zap.Must(zap.NewDevelopment()).Sugar()

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "resolv.conf")
			if tc.resolvConf != "" {
				if err := os.WriteFile(path, []byte(tc.resolvConf), 0600); err != nil {
					t.Fatalf("writing resolv.conf: %v", err)
				}
			}

			if got := reconciler.ClusterDomain(tc.namespace, logger, reconciler.WithResolvConfPath(path)); got != tc.want {
				t.Errorf("ClusterDomain() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTruncateLabelValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // empty means expect input unchanged
	}{
		{
			name:  "short-value-unchanged",
			input: "my-service",
		},
		{
			name:  "exactly-63-chars-unchanged",
			input: strings.Repeat("a", 63),
		},
		{
			name:  "64-chars-gets-truncated",
			input: strings.Repeat("a", 64),
		},
		{
			name:  "very-long-value-gets-truncated",
			input: "tailscale-nginx-clickhouse-o11y-server-https-with-extra-long-suffix-that-exceeds-limit",
		},
		{
			name:  "253-chars-max-k8s-resource-name",
			input: strings.Repeat("x", 253),
		},
		{
			name:  "empty-string-unchanged",
			input: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reconciler.TruncateLabelValue(tt.input)
			if len(got) > 63 {
				t.Errorf("reconciler.TruncateLabelValue(%q) = %q (len %d), exceeds 63 chars", tt.input, got, len(got))
			}
			if len(tt.input) <= 63 && got != tt.input {
				t.Errorf("reconciler.TruncateLabelValue(%q) = %q, want unchanged input", tt.input, got)
			}
			if len(tt.input) > 63 && got == tt.input {
				t.Errorf("reconciler.TruncateLabelValue(%q) was not truncated", tt.input)
			}
		})
	}
}

func TestTruncateLabelValueDeterministic(t *testing.T) {
	input := strings.Repeat("a", 100)
	first := reconciler.TruncateLabelValue(input)
	for range 10 {
		got := reconciler.TruncateLabelValue(input)
		if got != first {
			t.Fatalf("non-deterministic: got %q, want %q", got, first)
		}
	}
}

func TestTruncateLabelValueUniqueness(t *testing.T) {
	// Two inputs sharing a long prefix but differing at the end should produce different outputs.
	a := strings.Repeat("a", 100) + "-one"
	b := strings.Repeat("a", 100) + "-two"
	if reconciler.TruncateLabelValue(a) == reconciler.TruncateLabelValue(b) {
		t.Errorf("collision: %q and %q produce the same truncated label", a, b)
	}
}

func TestSetConnectorCondition(t *testing.T) {
	cn := tsapi.Connector{}
	clock := tstest.NewClock(tstest.ClockOpts{})
	fakeNow := metav1.NewTime(clock.Now().Truncate(time.Second))
	fakePast := metav1.NewTime(clock.Now().Truncate(time.Second).Add(-5 * time.Minute))
	zl, err := zap.NewDevelopment()
	assert.Nil(t, err)

	// Set up a new condition
	reconciler.SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "someReason", "someMsg", 1, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ConnectorReady),
					Status:             metav1.ConditionTrue,
					Reason:             "someReason",
					Message:            "someMsg",
					ObservedGeneration: 1,
					LastTransitionTime: fakeNow,
				},
			},
		},
	})

	// Modify status of an existing condition
	cn.Status = tsapi.ConnectorStatus{
		Conditions: []metav1.Condition{
			{
				Type:               string(tsapi.ConnectorReady),
				Status:             metav1.ConditionFalse,
				Reason:             "someReason",
				Message:            "someMsg",
				ObservedGeneration: 1,
				LastTransitionTime: fakePast,
			},
		},
	}
	reconciler.SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "anotherReason", "anotherMsg", 2, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ConnectorReady),
					Status:             metav1.ConditionTrue,
					Reason:             "anotherReason",
					Message:            "anotherMsg",
					ObservedGeneration: 2,
					LastTransitionTime: fakeNow,
				},
			},
		},
	})

	// Don't modify last transition time if status hasn't changed
	cn.Status = tsapi.ConnectorStatus{
		Conditions: []metav1.Condition{
			{
				Type:               string(tsapi.ConnectorReady),
				Status:             metav1.ConditionTrue,
				Reason:             "someReason",
				Message:            "someMsg",
				ObservedGeneration: 1,
				LastTransitionTime: fakePast,
			},
		},
	}
	reconciler.SetConnectorCondition(&cn, tsapi.ConnectorReady, metav1.ConditionTrue, "anotherReason", "anotherMsg", 2, clock, zl.Sugar())
	assert.Equal(t, cn, tsapi.Connector{
		Status: tsapi.ConnectorStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ConnectorReady),
					Status:             metav1.ConditionTrue,
					Reason:             "anotherReason",
					Message:            "anotherMsg",
					ObservedGeneration: 2,
					LastTransitionTime: fakePast,
				},
			},
		},
	})
}
