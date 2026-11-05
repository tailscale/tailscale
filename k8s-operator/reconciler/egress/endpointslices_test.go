// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package egress_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler"
	"tailscale.com/k8s-operator/reconciler/egress"
	"tailscale.com/k8s-operator/reconciler/reconcilertest"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/util/mak"
)

func TestTailscaleEgressEndpointSlices(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{})
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.bar.ts.net",
				reconciler.AnnotationProxyGroup:        "foo",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Selector:     nil,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: "TCP",
					Port:     80,
				},
			},
		},
		Status: corev1.ServiceStatus{
			Conditions: []metav1.Condition{
				condition(tsapi.EgressSvcConfigured, metav1.ConditionTrue, "", "", clock),
				condition(tsapi.EgressSvcValid, metav1.ConditionTrue, "", "", clock),
			},
		},
	}
	port := randomPort()
	cm := configMapForSvc(t, svc, port)
	fc := reconcilertest.NewClientBuilder().
		WithObjects(svc, cm).
		WithStatusSubresource(svc).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	er := egress.NewEndpointSliceReconciler(egress.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: "operator-ns",
		Logger:             zl.Sugar(),
	})
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "operator-ns",
			Labels: map[string]string{
				reconciler.LabelParentName:      "test",
				reconciler.LabelParentNamespace: "default",
				"tailscale.com/svc-type":        "egress",
				reconciler.LabelProxyGroup:      "foo"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	reconcilertest.MustCreate(t, fc, eps)

	t.Run("no_proxy_group_resources", func(t *testing.T) {
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo") // should not error
	})

	t.Run("no_pods_ready_to_route_traffic", func(t *testing.T) {
		pod, stateS := podAndSecretForProxyGroup("foo")
		reconcilertest.MustCreate(t, fc, pod)
		reconcilertest.MustCreate(t, fc, stateS)
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo") // should not error
	})

	t.Run("pods_are_ready_to_route_traffic", func(t *testing.T) {
		pod, stateS := podAndSecretForProxyGroup("foo")
		stBs := serviceStatusForPodIPs(t, svc, pod.Status.PodIPs[0].IP, "", port)
		reconcilertest.MustUpdate(t, fc, "operator-ns", stateS.Name, func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo")
		eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{"10.0.0.1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		})
		reconcilertest.ExpectEqual(t, fc, eps)
	})
	t.Run("status_does_not_match_pod_ip", func(t *testing.T) {
		_, stateS := podAndSecretForProxyGroup("foo")                // replica Pod has IP 10.0.0.1
		stBs := serviceStatusForPodIPs(t, svc, "10.0.0.2", "", port) // status is for a Pod with IP 10.0.0.2
		reconcilertest.MustUpdate(t, fc, "operator-ns", stateS.Name, func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo")
		eps.Endpoints = []discoveryv1.Endpoint{}
		reconcilertest.ExpectEqual(t, fc, eps)
	})

	// Dual-stack.
	epsV6 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-ipv6",
			Namespace: "operator-ns",
			Labels: map[string]string{
				reconciler.LabelParentName:      "test",
				reconciler.LabelParentNamespace: "default",
				"tailscale.com/svc-type":        "egress",
				reconciler.LabelProxyGroup:      "foo",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	reconcilertest.MustCreate(t, fc, epsV6)
	t.Run("dual_stack_pod_ready_to_route", func(t *testing.T) {
		reconcilertest.MustDeleteAll(t, fc, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foo-0", Namespace: "operator-ns"}})
		dualPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-0",
				Namespace: "operator-ns",
				Labels:    reconciler.ProxyGroupLabels("foo", nil),
				UID:       "foo",
			},
			Status: corev1.PodStatus{
				PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}},
			},
		}
		reconcilertest.MustCreate(t, fc, dualPod)
		stBs := serviceStatusForPodIPs(t, svc, "10.0.0.1", "fd00::1", port)
		reconcilertest.MustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo")
		eps.Endpoints = []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		}}
		reconcilertest.ExpectEqual(t, fc, eps)
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo-ipv6")
		epsV6.Endpoints = []discoveryv1.Endpoint{{
			Addresses: []string{"fd00::1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		}}
		reconcilertest.ExpectEqual(t, fc, epsV6)
	})

	// IPv6-only.
	t.Run("ipv4_only_pod_skipped_for_ipv6_slice", func(t *testing.T) {
		reconcilertest.MustDeleteAll(t, fc, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foo-0", Namespace: "operator-ns"}})
		ipv4Pod, _ := podAndSecretForProxyGroup("foo")
		reconcilertest.MustCreate(t, fc, ipv4Pod)
		stBs := serviceStatusForPodIPs(t, svc, "10.0.0.1", "", port)
		reconcilertest.MustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo-ipv6")
		// IPv4-only pod should not appear in the IPv6 EndpointSlice.
		epsV6.Endpoints = []discoveryv1.Endpoint{}
		reconcilertest.ExpectEqual(t, fc, epsV6)
	})
	ipv6Pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-0",
			Namespace: "operator-ns",
			Labels:    reconciler.ProxyGroupLabels("foo", nil),
			UID:       "foo",
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: "fd00::1"}},
		},
	}
	t.Run("ipv6_status_does_not_match_pod_ip", func(t *testing.T) {
		reconcilertest.MustDeleteAll(t, fc, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foo-0", Namespace: "operator-ns"}})
		reconcilertest.MustCreate(t, fc, ipv6Pod)
		stBs := serviceStatusForPodIPs(t, svc, "", "fd00::99", port)
		reconcilertest.MustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo-ipv6")
		epsV6.Endpoints = []discoveryv1.Endpoint{}
		reconcilertest.ExpectEqual(t, fc, epsV6)
	})
	t.Run("ipv6_pod_ready_to_route", func(t *testing.T) {
		stBs := serviceStatusForPodIPs(t, svc, "", ipv6Pod.Status.PodIPs[0].IP, port)
		reconcilertest.MustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo-ipv6")
		epsV6.Endpoints = append(epsV6.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{"fd00::1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		})
		reconcilertest.ExpectEqual(t, fc, epsV6)
	})
}

// TestEgressEndpointSliceEndpointsSorted verifies that endpoints are written in a deterministic (Hostname/UID
// sorted) order and that a second reconcile over an unchanged ready set does not rewrite the slice (a needless
// write would re-trigger this reconciler via its own EndpointSlice watch - see tailscale/tailscale#20916).
func TestEgressEndpointSliceEndpointsSorted(t *testing.T) {
	clock := tstest.NewClock(tstest.ClockOpts{})
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				reconciler.AnnotationTailnetTargetFQDN: "foo.bar.ts.net",
				reconciler.AnnotationProxyGroup:        "foo",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Ports:        []corev1.ServicePort{{Name: "http", Protocol: "TCP", Port: 80}},
		},
		Status: corev1.ServiceStatus{
			Conditions: []metav1.Condition{
				condition(tsapi.EgressSvcConfigured, metav1.ConditionTrue, "", "", clock),
				condition(tsapi.EgressSvcValid, metav1.ConditionTrue, "", "", clock),
			},
		},
	}
	port := randomPort()
	cm := configMapForSvc(t, svc, port)
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "operator-ns",
			Labels: map[string]string{
				reconciler.LabelParentName:      "test",
				reconciler.LabelParentNamespace: "default",
				"tailscale.com/svc-type":        "egress",
				reconciler.LabelProxyGroup:      "foo",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	fc := reconcilertest.NewClientBuilder().
		WithObjects(svc, cm).
		WithStatusSubresource(svc).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	er := egress.NewEndpointSliceReconciler(egress.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: "operator-ns",
		Logger:             zl.Sugar(),
	})
	reconcilertest.MustCreate(t, fc, eps)

	// Two ready Pods whose UIDs sort in the opposite order to their creation, so a stable sort is observable.
	for _, p := range []struct {
		uid string
		ip  string
	}{{"pod-b", "10.0.0.2"}, {"pod-a", "10.0.0.1"}} {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.uid,
				Namespace: "operator-ns",
				Labels:    reconciler.ProxyGroupLabels("foo", nil),
				UID:       types.UID(p.uid),
			},
			Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: p.ip}}},
		}
		reconcilertest.MustCreate(t, fc, pod)
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      p.uid,
				Namespace: "operator-ns",
				Labels:    stateSecretLabels("foo"),
			},
		}
		stBs := serviceStatusForPodIPs(t, svc, p.ip, "", port)
		mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		reconcilertest.MustCreate(t, fc, s)
	}

	reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo")
	got := &discoveryv1.EndpointSlice{}
	if err := fc.Get(t.Context(), types.NamespacedName{Name: "foo", Namespace: "operator-ns"}, got); err != nil {
		t.Fatalf("getting EndpointSlice: %v", err)
	}
	if len(got.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(got.Endpoints))
	}
	if h0, h1 := *got.Endpoints[0].Hostname, *got.Endpoints[1].Hostname; h0 != "pod-a" || h1 != "pod-b" {
		t.Errorf("endpoints not sorted by Hostname: got [%q, %q], want [\"pod-a\", \"pod-b\"]", h0, h1)
	}

	// A second reconcile over the unchanged ready set must not rewrite the slice.
	rvBefore := got.ResourceVersion
	reconcilertest.ExpectReconciled(t, er, "operator-ns", "foo")
	after := &discoveryv1.EndpointSlice{}
	if err := fc.Get(t.Context(), types.NamespacedName{Name: "foo", Namespace: "operator-ns"}, after); err != nil {
		t.Fatalf("getting EndpointSlice: %v", err)
	}
	if after.ResourceVersion != rvBefore {
		t.Errorf("EndpointSlice was rewritten on a no-op reconcile: resourceVersion %s -> %s", rvBefore, after.ResourceVersion)
	}
}

func configMapForSvc(t *testing.T, svc *corev1.Service, p uint16) *corev1.ConfigMap {
	t.Helper()
	ports := make(map[egressservices.PortMap]struct{})
	for _, port := range svc.Spec.Ports {
		ports[egressservices.PortMap{Protocol: string(port.Protocol), MatchPort: p, TargetPort: uint16(port.Port)}] = struct{}{}
	}
	cfg := egressservices.Config{
		Ports: ports,
	}
	if fqdn := svc.Annotations[reconciler.AnnotationTailnetTargetFQDN]; fqdn != "" {
		cfg.TailnetTarget = egressservices.TailnetTarget{FQDN: fqdn}
	}
	if ip := svc.Annotations[reconciler.AnnotationTailnetTargetIP]; ip != "" {
		cfg.TailnetTarget = egressservices.TailnetTarget{IP: ip}
	}
	name := tailnetSvcName(svc)
	cfgs := egressservices.Configs{name: cfg}
	bs, err := json.Marshal(&cfgs)
	if err != nil {
		t.Fatalf("error marshalling config: %v", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      reconciler.ProxyGroupEgressConfigMapName(svc.Annotations[reconciler.AnnotationProxyGroup]),
			Namespace: "operator-ns",
		},
		BinaryData: map[string][]byte{egressservices.KeyEgressServices: bs},
	}
	return cm
}

func serviceStatusForPodIPs(t *testing.T, svc *corev1.Service, ipv4, ipv6 string, p uint16) []byte {
	t.Helper()
	ports := make(map[egressservices.PortMap]struct{})
	for _, port := range svc.Spec.Ports {
		ports[egressservices.PortMap{Protocol: string(port.Protocol), MatchPort: p, TargetPort: uint16(port.Port)}] = struct{}{}
	}
	svcSt := egressservices.ServiceStatus{Ports: ports}
	if fqdn := svc.Annotations[reconciler.AnnotationTailnetTargetFQDN]; fqdn != "" {
		svcSt.TailnetTarget = egressservices.TailnetTarget{FQDN: fqdn}
	}
	if ip := svc.Annotations[reconciler.AnnotationTailnetTargetIP]; ip != "" {
		svcSt.TailnetTarget = egressservices.TailnetTarget{IP: ip}
	}
	svcName := tailnetSvcName(svc)
	st := egressservices.Status{
		PodIPv4:  ipv4,
		PodIPv6:  ipv6,
		Services: map[string]*egressservices.ServiceStatus{svcName: &svcSt},
	}
	bs, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("error marshalling service status: %v", err)
	}
	return bs
}

func podAndSecretForProxyGroup(pg string) (*corev1.Pod, *corev1.Secret) {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-0", pg),
			Namespace: "operator-ns",
			Labels:    reconciler.ProxyGroupLabels(pg, nil),
			UID:       "foo",
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{
				{IP: "10.0.0.1"},
			},
		},
	}
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-0", pg),
			Namespace: "operator-ns",
			Labels:    stateSecretLabels(pg),
		},
	}
	return p, s
}

func randomPort() uint16 {
	return uint16(rand.Int32N(1000) + 1000)
}

// stateSecretLabels returns the labels that the ProxyGroup reconciler sets on the state Secrets of the named ProxyGroup.
func stateSecretLabels(pgName string) map[string]string {
	return reconciler.ProxyGroupLabels(pgName, map[string]string{
		kubetypes.LabelSecretType: kubetypes.LabelSecretTypeState,
	})
}
