// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/routeacceptor"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/kube/routesources"
)

func newSourcesReconciler(t *testing.T, objs ...client.Object) (*routeacceptor.SourcesReconciler, client.Client) {
	t.Helper()
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(objs...).
		WithStatusSubresource(&tsapi.RouteAcceptor{}).
		Build()
	r := routeacceptor.NewSourcesReconciler(routeacceptor.SourcesReconcilerOptions{
		Client:             cl,
		PodReader:          cl,
		TailscaleNamespace: tailscaleNamespace,
		Logger:             logger.Sugar(),
	})
	return r, cl
}

func mustReconcileSources(t *testing.T, r *routeacceptor.SourcesReconciler) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), reconcile.Request{NamespacedName: types.NamespacedName{Name: raName}}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
}

func newPod(name, namespace, node string, labels map[string]string, ips ...string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: node},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for _, ip := range ips {
		pod.Status.PodIPs = append(pod.Status.PodIPs, corev1.PodIP{IP: ip})
	}
	return pod
}

func newNamespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// routeSourcesOf returns the document written into the node's state Secret, or nil.
func routeSourcesOf(t *testing.T, cl client.Client, node string) *routesources.Document {
	t.Helper()
	var s corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: tailscaleNamespace, Name: dsName + "-" + node}, &s); err != nil {
		t.Fatalf("getting state Secret for %s: %v", node, err)
	}
	b := s.Data[kubetypes.KeyRouteSources]
	if b == nil {
		return nil
	}
	doc, err := routesources.Parse(b)
	if err != nil {
		t.Fatalf("parsing route sources of %s: %v", node, err)
	}
	return doc
}

func ipStrings(ips []netip.Addr) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}

func sourcesRouteAcceptor(spec tsapi.RouteAcceptorSpec, clusterCIDRs ...string) *tsapi.RouteAcceptor {
	ra := newRouteAcceptor(spec)
	ra.Status.ClusterCIDRs = clusterCIDRs
	return ra
}

var testSources = []tsapi.RouteAcceptorSource{
	{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
	{
		PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"team": "data"}},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		Routes:            tsapi.Routes{"10.20.0.0/16"},
	},
}

func TestSources_WritesDocumentsPerNode(t *testing.T) {
	t.Parallel()
	r, cl := newSourcesReconciler(t,
		sourcesRouteAcceptor(tsapi.RouteAcceptorSpec{Sources: testSources}, "10.244.0.0/16", "10.96.0.0/12"),
		newStateSecret("node-a", nil),
		newStateSecret("node-b", nil),
		newNamespace("prod", map[string]string{"env": "prod"}),
		newNamespace("dev", nil),
		// Selected by the first entry: every route.
		newPod("web-1", "dev", "node-a", map[string]string{"app": "web"}, "10.244.0.5"),
		newPod("web-2", "dev", "node-b", map[string]string{"app": "web"}, "10.244.1.7", "fd00::7"),
		// Selected by the second entry: 10.20.0.0/16 only.
		newPod("data-1", "prod", "node-a", map[string]string{"team": "data"}, "10.244.0.9"),
		// Not selected: wrong namespace for the second entry.
		newPod("data-2", "dev", "node-b", map[string]string{"team": "data"}, "10.244.1.9"),
		// Selected by both entries: the union is every route.
		newPod("both-1", "prod", "node-b", map[string]string{"app": "web", "team": "data"}, "10.244.1.11"),
		// Never selected: host network, finished, or without an address yet.
		func() *corev1.Pod {
			p := newPod("host-1", "dev", "node-a", map[string]string{"app": "web"}, "192.168.1.10")
			p.Spec.HostNetwork = true
			return p
		}(),
		func() *corev1.Pod {
			p := newPod("done-1", "dev", "node-b", map[string]string{"app": "web"}, "10.244.1.20")
			p.Status.Phase = corev1.PodSucceeded
			return p
		}(),
		newPod("pending-1", "dev", "node-a", map[string]string{"app": "web"}),
	)
	mustReconcileSources(t, r)

	docA := routeSourcesOf(t, cl, "node-a")
	if docA == nil {
		t.Fatal("no document for node-a")
	}
	if got, want := docA.ClusterCIDRs, []netip.Prefix{netip.MustParsePrefix("10.96.0.0/12"), netip.MustParsePrefix("10.244.0.0/16")}; !slices.Equal(got, want) {
		t.Errorf("node-a clusterCIDRs = %v, want %v", got, want)
	}
	if len(docA.Groups) != 2 {
		t.Fatalf("node-a groups = %+v, want 2", docA.Groups)
	}
	// Groups are sorted with the all-routes group first.
	if docA.Groups[0].Routes != nil || !slices.Equal(ipStrings(docA.Groups[0].IPs), []string{"10.244.0.5"}) {
		t.Errorf("node-a all-routes group = %+v", docA.Groups[0])
	}
	restricted := docA.Groups[1]
	if !slices.Equal(restricted.Routes, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) || !slices.Equal(ipStrings(restricted.IPs), []string{"10.244.0.9"}) {
		t.Errorf("node-a restricted group = %+v", restricted)
	}
	if restricted.Table < routesources.TableBase || restricted.Table >= routesources.TableBase+routesources.TableCount {
		t.Errorf("node-a restricted group table = %d", restricted.Table)
	}

	docB := routeSourcesOf(t, cl, "node-b")
	if docB == nil {
		t.Fatal("no document for node-b")
	}
	if len(docB.Groups) != 1 || docB.Groups[0].Routes != nil {
		t.Fatalf("node-b groups = %+v, want one all-routes group", docB.Groups)
	}
	if got, want := ipStrings(docB.Groups[0].IPs), []string{"10.244.1.7", "10.244.1.11", "fd00::7"}; !slices.Equal(got, want) {
		t.Errorf("node-b addresses = %v, want %v", got, want)
	}

	// A second reconcile with nothing changed does not touch the Secrets.
	var before corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: tailscaleNamespace, Name: dsName + "-node-a"}, &before); err != nil {
		t.Fatal(err)
	}
	mustReconcileSources(t, r)
	var after corev1.Secret
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: tailscaleNamespace, Name: dsName + "-node-a"}, &after); err != nil {
		t.Fatal(err)
	}
	if before.ResourceVersion != after.ResourceVersion {
		t.Errorf("state Secret rewritten without changes: resourceVersion %s -> %s", before.ResourceVersion, after.ResourceVersion)
	}

	// The document follows the Pods.
	var pod corev1.Pod
	if err := cl.Get(context.Background(), types.NamespacedName{Namespace: "dev", Name: "web-1"}, &pod); err != nil {
		t.Fatal(err)
	}
	if err := cl.Delete(context.Background(), &pod); err != nil {
		t.Fatal(err)
	}
	mustReconcileSources(t, r)
	docA = routeSourcesOf(t, cl, "node-a")
	if len(docA.Groups) != 1 || docA.Groups[0].Routes == nil {
		t.Errorf("node-a groups after deleting web-1 = %+v, want only the restricted group", docA.Groups)
	}

	// Removing spec.sources removes the documents.
	ra := getRouteAcceptor(t, cl)
	ra.Spec.Sources = nil
	if err := cl.Update(context.Background(), ra); err != nil {
		t.Fatal(err)
	}
	mustReconcileSources(t, r)
	for _, node := range []string{"node-a", "node-b"} {
		if doc := routeSourcesOf(t, cl, node); doc != nil {
			t.Errorf("document for %s still present after removing spec.sources: %+v", node, doc)
		}
	}
}

func TestSources_WaitsForClusterCIDRs(t *testing.T) {
	t.Parallel()
	r, cl := newSourcesReconciler(t,
		sourcesRouteAcceptor(tsapi.RouteAcceptorSpec{Sources: testSources}),
		newStateSecret("node-a", nil),
		newPod("web-1", "dev", "node-a", map[string]string{"app": "web"}, "10.244.0.5"),
	)
	mustReconcileSources(t, r)
	if doc := routeSourcesOf(t, cl, "node-a"); doc != nil {
		t.Errorf("document written without cluster CIDRs: %+v", doc)
	}
}

func TestSources_EgressGatewayListsEveryPodOnEveryNode(t *testing.T) {
	t.Parallel()
	r, cl := newSourcesReconciler(t,
		sourcesRouteAcceptor(tsapi.RouteAcceptorSpec{
			Sources: testSources,
			Cilium:  &tsapi.RouteAcceptorCilium{EgressGateway: &tsapi.CiliumEgressGateway{}},
		}, "10.244.0.0/16"),
		newStateSecret("node-a", nil),
		newStateSecret("node-b", nil),
		newPod("web-1", "dev", "node-a", map[string]string{"app": "web"}, "10.244.0.5"),
		newPod("web-2", "dev", "node-b", map[string]string{"app": "web"}, "10.244.1.7"),
	)
	mustReconcileSources(t, r)
	for _, node := range []string{"node-a", "node-b"} {
		doc := routeSourcesOf(t, cl, node)
		if doc == nil || len(doc.Groups) != 1 {
			t.Fatalf("document for %s = %+v", node, doc)
		}
		if got, want := ipStrings(doc.Groups[0].IPs), []string{"10.244.0.5", "10.244.1.7"}; !slices.Equal(got, want) {
			t.Errorf("%s addresses = %v, want every selected Pod %v", node, got, want)
		}
	}
}

func TestSources_UnselectedNodeGetsEmptyDocument(t *testing.T) {
	t.Parallel()
	r, cl := newSourcesReconciler(t,
		sourcesRouteAcceptor(tsapi.RouteAcceptorSpec{Sources: testSources}, "10.244.0.0/16"),
		newStateSecret("node-a", nil),
		newPod("other", "dev", "node-a", map[string]string{"app": "other"}, "10.244.0.5"),
	)
	mustReconcileSources(t, r)
	doc := routeSourcesOf(t, cl, "node-a")
	if doc == nil {
		t.Fatal("no document for node-a: the device needs the cluster CIDRs even with no Pod to route")
	}
	if len(doc.Groups) != 0 {
		t.Errorf("groups = %+v, want none", doc.Groups)
	}
}
