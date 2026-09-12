// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package routeacceptor

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/event"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
)

func TestStateSecretPredicateIgnoresRouteSources(t *testing.T) {
	old := &corev1.Secret{Data: map[string][]byte{kubetypes.KeyDeviceIPs: []byte(`["100.64.0.1"]`)}}
	sourcesOnly := old.DeepCopy()
	sourcesOnly.Data[kubetypes.KeyRouteSources] = []byte(`{"version":1}`)
	if stateSecretPredicate.Update(event.UpdateEvent{ObjectOld: old, ObjectNew: sourcesOnly}) {
		t.Error("an update that only writes route sources triggered the RouteAcceptor reconciler")
	}
	routes := sourcesOnly.DeepCopy()
	routes.Data[kubetypes.KeyAcceptedRoutes] = []byte(`["10.20.0.0/16"]`)
	if !stateSecretPredicate.Update(event.UpdateEvent{ObjectOld: sourcesOnly, ObjectNew: routes}) {
		t.Error("an update of the accepted routes was ignored")
	}
	relabelled := routes.DeepCopy()
	relabelled.Labels = map[string]string{"x": "y"}
	if !stateSecretPredicate.Update(event.UpdateEvent{ObjectOld: routes, ObjectNew: relabelled}) {
		t.Error("a label change was ignored")
	}
}

func TestPodSourcePredicate(t *testing.T) {
	pod := func(ip string) *corev1.Pod {
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Labels: map[string]string{"app": "web"}},
			Spec:       corev1.PodSpec{NodeName: "node-a"},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
		if ip != "" {
			p.Status.PodIPs = []corev1.PodIP{{IP: ip}}
		}
		return p
	}
	if podSourcePredicate.Create(event.TypedCreateEvent[*corev1.Pod]{Object: pod("")}) {
		t.Error("a Pod without an address triggered a reconcile")
	}
	if !podSourcePredicate.Create(event.TypedCreateEvent[*corev1.Pod]{Object: pod("10.244.0.5")}) {
		t.Error("a Pod with an address did not trigger a reconcile")
	}
	if podSourcePredicate.Update(event.TypedUpdateEvent[*corev1.Pod]{ObjectOld: pod("10.244.0.5"), ObjectNew: pod("10.244.0.5")}) {
		t.Error("an update without relevant changes triggered a reconcile")
	}
	if !podSourcePredicate.Update(event.TypedUpdateEvent[*corev1.Pod]{ObjectOld: pod(""), ObjectNew: pod("10.244.0.5")}) {
		t.Error("a Pod getting an address did not trigger a reconcile")
	}
	relabelled := pod("10.244.0.5")
	relabelled.Labels["app"] = "db"
	if !podSourcePredicate.Update(event.TypedUpdateEvent[*corev1.Pod]{ObjectOld: pod("10.244.0.5"), ObjectNew: relabelled}) {
		t.Error("a label change did not trigger a reconcile")
	}
	host := pod("192.168.1.1")
	host.Spec.HostNetwork = true
	if podSourcePredicate.Create(event.TypedCreateEvent[*corev1.Pod]{Object: host}) {
		t.Error("a host-network Pod triggered a reconcile")
	}
}

func TestCompileSources(t *testing.T) {
	compiled, err := compileSources([]tsapi.RouteAcceptorSource{
		{},
		{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}, NamespaceSelector: &metav1.LabelSelector{}, Routes: tsapi.Routes{"10.20.0.0/16"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// An entry without selectors selects every Pod in every namespace, to every route.
	if !compiled[0].pods.Matches(labels.Set{"anything": "goes"}) || compiled[0].namespaces != nil || compiled[0].routes != nil {
		t.Errorf("empty entry compiled to %+v", compiled[0])
	}
	// An empty namespaceSelector selects every namespace, unlike a nil one converted naively.
	if !compiled[1].namespaces.Matches(labels.Set{}) {
		t.Error("empty namespaceSelector does not match a namespace without labels")
	}
	if !compiled[1].pods.Matches(labels.Set{"app": "web"}) || compiled[1].pods.Matches(labels.Set{"app": "db"}) {
		t.Error("podSelector compiled wrongly")
	}
	if len(compiled[1].routes) != 1 {
		t.Errorf("routes = %v", compiled[1].routes)
	}
	if _, err := compileSources([]tsapi.RouteAcceptorSource{{Routes: tsapi.Routes{"nope"}}}); err == nil {
		t.Error("invalid route accepted")
	}
}
