// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/peerrelay"
)

// TestReconciler_Metrics walks a PeerRelay through the ProxyClass spec.metrics settings.
func TestReconciler_Metrics(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       tsapi.PeerRelaySpec{ProxyClass: "metrics"},
	}

	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "metrics"},
		Spec:       tsapi.ProxyClassSpec{Metrics: &tsapi.Metrics{Enable: true}},
		Status:     readyProxyClassStatus(),
	}

	// The fake client registers the unstructured ServiceMonitor kind into its scheme, which races on a shared one.
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, tsapi.AddToScheme, apiextensionsv1.AddToScheme} {
		if err = add(scheme); err != nil {
			t.Fatal(err)
		}
	}

	fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
		WithScheme(scheme).
		WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
		WithObjects(pr, pc).
		Build()

	r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: tailscaleNamespace,
		ProxyImage:         testProxyImage,
		DefaultTags:        []string{"tag:test-peer-relay"},
		Clients:            &fakeClientProvider{client: &fakeTSClient{}},
		Resolver:           testResolver,
		Logger:             logger.Sugar(),
	})

	reconcileOnce := func() {
		t.Helper()
		if _, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}
	}

	updateProxyClass := func(fn func(*tsapi.ProxyClass)) {
		t.Helper()
		var current tsapi.ProxyClass
		if err := fc.Get(t.Context(), types.NamespacedName{Name: "metrics"}, &current); err != nil {
			t.Fatal(err)
		}
		fn(&current)
		if err := fc.Update(t.Context(), &current); err != nil {
			t.Fatal(err)
		}
	}

	podLabels := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource-type": "peerrelay",
		"tailscale.com/parent-resource":      "test",
	}

	svcLabels := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource-type": "peerrelay",
		"tailscale.com/parent-resource":      "test",
		"ts_proxy_type":                      "peerrelay",
		"ts_proxy_parent_name":               "test",
		"ts_prom_job":                        "ts_peerrelay_test",
	}

	// 1. Metrics enabled: the pod serves /metrics and a metrics Service selects it.
	reconcileOnce()
	assertMetricsEnabled(t, fc, true)

	svc := getMetricsService(t, fc)
	if svc == nil {
		t.Fatal("expected metrics Service to be created")
	}

	if svc.Spec.Type != corev1.ServiceTypeClusterIP {
		t.Errorf("metrics Service type = %q, want %q", svc.Spec.Type, corev1.ServiceTypeClusterIP)
	}

	wantPorts := []corev1.ServicePort{{Name: "metrics", Protocol: corev1.ProtocolTCP, Port: 9002}}
	if diff := cmp.Diff(wantPorts, svc.Spec.Ports); diff != "" {
		t.Errorf("metrics Service ports mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(podLabels, svc.Spec.Selector); diff != "" {
		t.Errorf("metrics Service selector mismatch (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(svcLabels, svc.Labels); diff != "" {
		t.Errorf("metrics Service labels mismatch (-want +got):\n%s", diff)
	}

	if sm := getServiceMonitor(t, fc); sm != nil {
		t.Errorf("expected no ServiceMonitor while spec.metrics.serviceMonitor is unset, got %v", sm.Object)
	}

	// 2. ServiceMonitor enabled before its CRD is installed: there's nothing to create, and it isn't an error.
	updateProxyClass(func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics.ServiceMonitor = &tsapi.ServiceMonitor{Enable: true, Labels: tsapi.Labels{"team": "observability"}}
	})
	reconcileOnce()

	if sm := getServiceMonitor(t, fc); sm != nil {
		t.Errorf("expected no ServiceMonitor without the CRD installed, got %v", sm.Object)
	}

	// 3. CRD installed: the ServiceMonitor is created and selects the metrics Service.
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: "servicemonitors.monitoring.coreos.com"}}
	if err = fc.Create(t.Context(), crd); err != nil {
		t.Fatal(err)
	}
	reconcileOnce()

	sm := getServiceMonitor(t, fc)
	if sm == nil {
		t.Fatal("expected ServiceMonitor to be created")
	}

	wantSMLabels := map[string]string{"team": "observability"}
	for k, v := range svcLabels {
		wantSMLabels[k] = v
	}
	if diff := cmp.Diff(wantSMLabels, sm.GetLabels()); diff != "" {
		t.Errorf("ServiceMonitor labels mismatch (-want +got):\n%s", diff)
	}

	matchLabels := map[string]any{}
	for k, v := range svcLabels {
		matchLabels[k] = v
	}
	wantSpec := map[string]any{
		"selector":          map[string]any{"matchLabels": matchLabels},
		"endpoints":         []any{map[string]any{"port": "metrics"}},
		"namespaceSelector": map[string]any{"matchNames": []any{tailscaleNamespace}},
		"jobLabel":          "ts_prom_job",
		"targetLabels":      []any{"ts_proxy_type", "ts_proxy_parent_name"},
	}
	if diff := cmp.Diff(wantSpec, sm.Object["spec"]); diff != "" {
		t.Errorf("ServiceMonitor spec mismatch (-want +got):\n%s", diff)
	}

	owners := sm.GetOwnerReferences()
	if len(owners) != 1 || owners[0].Kind != "Service" || owners[0].Name != svc.Name || owners[0].UID != svc.UID {
		t.Errorf("ServiceMonitor owner references = %+v, want the metrics Service %q", owners, svc.Name)
	}

	// 4. ServiceMonitor labels changed: the existing ServiceMonitor picks them up.
	updateProxyClass(func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics.ServiceMonitor.Labels = tsapi.Labels{"team": "sre"}
	})
	reconcileOnce()

	if got := getServiceMonitor(t, fc).GetLabels()["team"]; got != "sre" {
		t.Errorf("ServiceMonitor label team = %q, want %q", got, "sre")
	}

	// 5. ServiceMonitor disabled: it is removed, but the metrics Service stays.
	updateProxyClass(func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics.ServiceMonitor.Enable = false
	})
	reconcileOnce()

	if sm := getServiceMonitor(t, fc); sm != nil {
		t.Errorf("expected ServiceMonitor to be deleted, got %v", sm.Object)
	}

	if getMetricsService(t, fc) == nil {
		t.Error("expected metrics Service to remain while metrics are enabled")
	}

	// 6. Metrics disabled: the metrics Service is removed and the pod stops serving /metrics.
	updateProxyClass(func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics = nil
	})
	reconcileOnce()
	assertMetricsEnabled(t, fc, false)

	if getMetricsService(t, fc) != nil {
		t.Error("expected metrics Service to be deleted once metrics are disabled")
	}

	// 7. PeerRelay deleted: its metrics Service goes with it.
	updateProxyClass(func(pc *tsapi.ProxyClass) {
		pc.Spec.Metrics = &tsapi.Metrics{Enable: true}
	})
	reconcileOnce()

	if getMetricsService(t, fc) == nil {
		t.Fatal("expected metrics Service to be recreated once metrics are re-enabled")
	}

	if err = fc.Delete(t.Context(), &tsapi.PeerRelay{ObjectMeta: metav1.ObjectMeta{Name: "test"}}); err != nil {
		t.Fatal(err)
	}
	reconcileOnce()

	if getMetricsService(t, fc) != nil {
		t.Error("expected metrics Service to be deleted with the PeerRelay")
	}
}

// assertMetricsEnabled checks whether the PeerRelay's tailscaled container is configured to serve /metrics.
func assertMetricsEnabled(t *testing.T, fc client.Client, want bool) {
	t.Helper()

	var ss appsv1.StatefulSet
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: "peerrelay-test"}, &ss); err != nil {
		t.Fatal(err)
	}

	var got bool
	for _, e := range ss.Spec.Template.Spec.Containers[0].Env {
		if e.Name == "TS_ENABLE_METRICS" && e.Value == "true" {
			got = true
		}
	}

	if got != want {
		t.Errorf("TS_ENABLE_METRICS=true set = %t, want %t; container env is %+v", got, want, ss.Spec.Template.Spec.Containers[0].Env)
	}
}

// getMetricsService returns the PeerRelay's metrics Service, or nil if it doesn't exist.
func getMetricsService(t *testing.T, fc client.Client) *corev1.Service {
	t.Helper()

	var svc corev1.Service
	err := fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: "peerrelay-test-metrics"}, &svc)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		t.Fatal(err)
	}

	return &svc
}

// getServiceMonitor returns the PeerRelay's ServiceMonitor, or nil if it doesn't exist.
func getServiceMonitor(t *testing.T, fc client.Client) *unstructured.Unstructured {
	t.Helper()

	sm := &unstructured.Unstructured{}
	sm.SetAPIVersion("monitoring.coreos.com/v1")
	sm.SetKind("ServiceMonitor")
	err := fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: "peerrelay-test-metrics"}, sm)
	switch {
	case apierrors.IsNotFound(err):
		return nil
	case err != nil:
		t.Fatal(err)
	}

	return sm
}
