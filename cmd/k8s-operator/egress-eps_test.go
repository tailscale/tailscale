// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
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
				AnnotationTailnetTargetFQDN: "foo.bar.ts.net",
				AnnotationProxyGroup:        "foo",
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
	// The egress EndpointSlices reconciler owns the slice's ports, which it
	// derives from the ClusterIP Service the egress Services reconciler creates.
	// Provide that Service so the reconciler can find it.
	clusterIPSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ts-test-clusterip",
			Namespace: "operator-ns",
			Labels:    egressSvcChildResourceLabels(svc),
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{Name: "http", Protocol: "TCP", Port: 80, TargetPort: intstr.FromInt(4003)},
			},
		},
	}
	epsPorts := epsPortsFromSvc(clusterIPSvc)
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(svc, cm, clusterIPSvc).
		WithStatusSubresource(svc).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	er := &egressEpsReconciler{
		Client:      fc,
		logger:      zl.Sugar(),
		tsNamespace: "operator-ns",
	}
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "operator-ns",
			// Full managed label set, as the egress Services reconciler would set
			// at creation. egress-eps does not write labels, so these must be
			// present on the created object for the reconciler to find the
			// ClusterIP Service and for the expected object to match.
			Labels: egressSvcEpsLabels(svc, clusterIPSvc),
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	mustCreate(t, fc, eps)
	// The egress EndpointSlices reconciler owns the slice's ports (derived from
	// the ClusterIP Service); it does not write labels. So the expected object
	// carries the ports it sets, and the labels it was created with.
	eps.Ports = epsPorts

	t.Run("no_proxy_group_resources", func(t *testing.T) {
		expectReconciled(t, er, "operator-ns", "foo") // should not error
	})

	t.Run("no_pods_ready_to_route_traffic", func(t *testing.T) {
		pod, stateS := podAndSecretForProxyGroup("foo")
		mustCreate(t, fc, pod)
		mustCreate(t, fc, stateS)
		expectReconciled(t, er, "operator-ns", "foo") // should not error
	})

	t.Run("pods_are_ready_to_route_traffic", func(t *testing.T) {
		pod, stateS := podAndSecretForProxyGroup("foo")
		stBs := serviceStatusForPodIPs(t, svc, pod.Status.PodIPs[0].IP, "", port)
		mustUpdate(t, fc, "operator-ns", stateS.Name, func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		expectReconciled(t, er, "operator-ns", "foo")
		eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{"10.0.0.1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		})
		expectEqual(t, fc, eps)
	})
	t.Run("no_write_when_unchanged", func(t *testing.T) {
		// With a stable set of ready Pods, ports and labels, repeated reconciles
		// must not rewrite the slice: the reflect.DeepEqual guard (plus
		// deterministic endpoint/port ordering) makes them no-ops. Because this
		// reconciler watches EndpointSlices, a needless Update would re-trigger it.
		before := &discoveryv1.EndpointSlice{}
		if err := fc.Get(t.Context(), types.NamespacedName{Name: "foo", Namespace: "operator-ns"}, before); err != nil {
			t.Fatalf("getting EndpointSlice: %v", err)
		}
		for range 3 {
			expectReconciled(t, er, "operator-ns", "foo")
		}
		after := &discoveryv1.EndpointSlice{}
		if err := fc.Get(t.Context(), types.NamespacedName{Name: "foo", Namespace: "operator-ns"}, after); err != nil {
			t.Fatalf("getting EndpointSlice: %v", err)
		}
		if before.ResourceVersion != after.ResourceVersion {
			t.Errorf("EndpointSlice rewritten on steady-state reconcile: resourceVersion %s -> %s", before.ResourceVersion, after.ResourceVersion)
		}
	})
	t.Run("labels_not_touched", func(t *testing.T) {
		// egress-eps owns only endpoints and ports; labels are owned by the egress
		// Services reconciler. So when it writes endpoints/ports via a merge patch,
		// it must not touch labels at all: an external label must survive, and a
		// managed label it does not read as input (LabelManagedBy) must NOT be
		// re-added by egress-eps (it is not egress-eps's responsibility). This
		// documents the ownership boundary and proves the merge patch does not
		// clobber or repair labels.
		mustUpdate(t, fc, "operator-ns", "foo", func(e *discoveryv1.EndpointSlice) {
			e.Labels["example.com/external"] = "keep-me"
			delete(e.Labels, discoveryv1.LabelManagedBy)
		})
		// Trigger a real endpoints change so egress-eps performs a merge patch.
		// Add asecond port to the ClusterIP Service so the slice's ports change.
		mustUpdate(t, fc, "operator-ns", clusterIPSvc.Name, func(s *corev1.Service) {
			s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{Name: "extra", Protocol: "TCP", Port: 8443, TargetPort: intstr.FromInt(4005)})
			clusterIPSvc.Spec.Ports = s.Spec.Ports
		})
		epsPorts = epsPortsFromSvc(clusterIPSvc)
		expectReconciled(t, er, "operator-ns", "foo")
		got := &discoveryv1.EndpointSlice{}
		if err := fc.Get(t.Context(), types.NamespacedName{Name: "foo", Namespace: "operator-ns"}, got); err != nil {
			t.Fatalf("getting EndpointSlice: %v", err)
		}
		if got.Labels["example.com/external"] != "keep-me" {
			t.Errorf("external label not preserved by merge patch: got %q", got.Labels["example.com/external"])
		}
		if _, ok := got.Labels[discoveryv1.LabelManagedBy]; ok {
			t.Errorf("egress-eps re-added managed label %s it does not own: %q", discoveryv1.LabelManagedBy, got.Labels[discoveryv1.LabelManagedBy])
		}
		eps.Labels = got.Labels
		eps.Ports = epsPorts
	})
	t.Run("reconciler_owns_ports", func(t *testing.T) {
		// A port change on the ClusterIP Service must propagate to the slice via
		// this reconciler - the egress Services reconciler no longer updates the
		// slice after creation (tailscale/tailscale#20916).
		mustUpdate(t, fc, "operator-ns", clusterIPSvc.Name, func(s *corev1.Service) {
			s.Spec.Ports = append(s.Spec.Ports, corev1.ServicePort{Name: "https", Protocol: "TCP", Port: 443, TargetPort: intstr.FromInt(4004)})
			clusterIPSvc.Spec.Ports = s.Spec.Ports
		})
		// Refresh the expected ports for this and all subsequent assertions.
		epsPorts = epsPortsFromSvc(clusterIPSvc)
		expectReconciled(t, er, "operator-ns", "foo")
		eps.Ports = epsPorts
		expectEqual(t, fc, eps)
	})
	t.Run("status_does_not_match_pod_ip", func(t *testing.T) {
		_, stateS := podAndSecretForProxyGroup("foo")                // replica Pod has IP 10.0.0.1
		stBs := serviceStatusForPodIPs(t, svc, "10.0.0.2", "", port) // status is for a Pod with IP 10.0.0.2
		mustUpdate(t, fc, "operator-ns", stateS.Name, func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		expectReconciled(t, er, "operator-ns", "foo")
		eps.Endpoints = []discoveryv1.Endpoint{}
		expectEqual(t, fc, eps)
	})

	// Dual-stack.
	epsV6 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-ipv6",
			Namespace: "operator-ns",
			// Full managed label set, as the egress Services reconciler would set
			// at creation (egress-eps does not write labels).
			// TODO(beckypauley): specify.
			Labels: egressSvcEpsLabels(svc, clusterIPSvc),
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	mustCreate(t, fc, epsV6)
	epsV6.Ports = epsPorts
	t.Run("dual_stack_pod_ready_to_route", func(t *testing.T) {
		mustDeleteAll(t, fc, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foo-0", Namespace: "operator-ns"}})
		dualPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo-0",
				Namespace: "operator-ns",
				Labels:    pgLabels("foo", nil),
				UID:       "foo",
			},
			Status: corev1.PodStatus{
				PodIPs: []corev1.PodIP{{IP: "10.0.0.1"}, {IP: "fd00::1"}},
			},
		}
		mustCreate(t, fc, dualPod)
		stBs := serviceStatusForPodIPs(t, svc, "10.0.0.1", "fd00::1", port)
		mustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		expectReconciled(t, er, "operator-ns", "foo")
		eps.Endpoints = []discoveryv1.Endpoint{{
			Addresses: []string{"10.0.0.1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		}}
		expectEqual(t, fc, eps)
		expectReconciled(t, er, "operator-ns", "foo-ipv6")
		epsV6.Endpoints = []discoveryv1.Endpoint{{
			Addresses: []string{"fd00::1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		}}
		expectEqual(t, fc, epsV6)
	})

	// IPv6-only.
	t.Run("ipv4_only_pod_skipped_for_ipv6_slice", func(t *testing.T) {
		mustDeleteAll(t, fc, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foo-0", Namespace: "operator-ns"}})
		ipv4Pod, _ := podAndSecretForProxyGroup("foo")
		mustCreate(t, fc, ipv4Pod)
		stBs := serviceStatusForPodIPs(t, svc, "10.0.0.1", "", port)
		mustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		expectReconciled(t, er, "operator-ns", "foo-ipv6")
		// IPv4-only pod should not appear in the IPv6 EndpointSlice.
		epsV6.Endpoints = []discoveryv1.Endpoint{}
		expectEqual(t, fc, epsV6)
	})
	ipv6Pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo-0",
			Namespace: "operator-ns",
			Labels:    pgLabels("foo", nil),
			UID:       "foo",
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: "fd00::1"}},
		},
	}
	t.Run("ipv6_status_does_not_match_pod_ip", func(t *testing.T) {
		mustDeleteAll(t, fc, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "foo-0", Namespace: "operator-ns"}})
		mustCreate(t, fc, ipv6Pod)
		stBs := serviceStatusForPodIPs(t, svc, "", "fd00::99", port)
		mustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		expectReconciled(t, er, "operator-ns", "foo-ipv6")
		epsV6.Endpoints = []discoveryv1.Endpoint{}
		expectEqual(t, fc, epsV6)
	})
	t.Run("ipv6_pod_ready_to_route", func(t *testing.T) {
		stBs := serviceStatusForPodIPs(t, svc, "", ipv6Pod.Status.PodIPs[0].IP, port)
		mustUpdate(t, fc, "operator-ns", "foo-0", func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
		expectReconciled(t, er, "operator-ns", "foo-ipv6")
		epsV6.Endpoints = append(epsV6.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{"fd00::1"},
			Hostname:  new("foo"),
			Conditions: discoveryv1.EndpointConditions{
				Serving:     new(true),
				Ready:       new(true),
				Terminating: new(false),
			},
		})
		expectEqual(t, fc, epsV6)
	})
}

// TestEgressEndpointSliceEndpointsSorted verifies that the endpoints written to
// an egress EndpointSlice are ordered deterministically (by Pod UID), so that an
// unchanged set of ready Pods always produces an identical slice regardless of
// the order the Pods are returned by the API. Without this, the reflect.DeepEqual
// guard in Reconcile would see spurious changes and, because the reconciler
// watches EndpointSlices, re-trigger itself.
func TestEgressEndpointSliceEndpointsSorted(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				AnnotationTailnetTargetFQDN: "foo.bar.ts.net",
				AnnotationProxyGroup:        "foo",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Ports:        []corev1.ServicePort{{Name: "http", Protocol: "TCP", Port: 80}},
		},
	}
	port := randomPort()
	cm := configMapForSvc(t, svc, port)
	clusterIPSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ts-test-clusterip",
			Namespace: "operator-ns",
			Labels:    egressSvcChildResourceLabels(svc),
		},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{Name: "http", Protocol: "TCP", Port: 80, TargetPort: intstr.FromInt(4003)}},
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(svc, cm, clusterIPSvc).
		WithStatusSubresource(svc).
		Build()
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	er := &egressEpsReconciler{Client: fc, logger: zl.Sugar(), tsNamespace: "operator-ns"}

	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "operator-ns",
			Labels: map[string]string{
				LabelParentName:              "test",
				LabelParentNamespace:         "default",
				labelSvcType:                 typeEgress,
				labelProxyGroup:              "foo",
				discoveryv1.LabelServiceName: clusterIPSvc.Name,
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	mustCreate(t, fc, eps)

	// Two ready Pods whose UIDs sort in the opposite order to their names, so a
	// name/creation-ordered Pod list would produce a different endpoint order
	// than the desired UID-sorted one.
	pods := []struct {
		name, uid, ip string
	}{
		{"foo-0", "zzz-uid", "10.0.0.1"},
		{"foo-1", "aaa-uid", "10.0.0.2"},
	}
	for _, p := range pods {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: "operator-ns", Labels: pgLabels("foo", nil), UID: types.UID(p.uid)},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: p.ip}}},
		}
		sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: p.name, Namespace: "operator-ns", Labels: pgSecretLabels("foo", kubetypes.LabelSecretTypeState)}}
		mustCreate(t, fc, pod)
		mustCreate(t, fc, sec)
		stBs := serviceStatusForPodIPs(t, svc, p.ip, "", port)
		mustUpdate(t, fc, "operator-ns", p.name, func(s *corev1.Secret) {
			mak.Set(&s.Data, egressservices.KeyEgressServices, stBs)
		})
	}

	expectReconciled(t, er, "operator-ns", "foo")
	got := &discoveryv1.EndpointSlice{}
	if err := fc.Get(t.Context(), types.NamespacedName{Name: "foo", Namespace: "operator-ns"}, got); err != nil {
		t.Fatalf("getting EndpointSlice: %v", err)
	}
	gotHostnames := make([]string, 0, len(got.Endpoints))
	for _, e := range got.Endpoints {
		if e.Hostname != nil {
			gotHostnames = append(gotHostnames, *e.Hostname)
		}
	}
	want := []string{"aaa-uid", "zzz-uid"} // sorted by UID
	if !slices.Equal(gotHostnames, want) {
		t.Errorf("endpoints not sorted by UID: got %v, want %v", gotHostnames, want)
	}
	// A second reconcile must not rewrite the slice (order is stable).
	rvBefore := got.ResourceVersion
	expectReconciled(t, er, "operator-ns", "foo")
	if err := fc.Get(t.Context(), types.NamespacedName{Name: "foo", Namespace: "operator-ns"}, got); err != nil {
		t.Fatalf("getting EndpointSlice: %v", err)
	}
	if got.ResourceVersion != rvBefore {
		t.Errorf("second reconcile rewrote the slice: resourceVersion %s -> %s", rvBefore, got.ResourceVersion)
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
	if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		cfg.TailnetTarget = egressservices.TailnetTarget{FQDN: fqdn}
	}
	if ip := svc.Annotations[AnnotationTailnetTargetIP]; ip != "" {
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
			Name:      pgEgressCMName(svc.Annotations[AnnotationProxyGroup]),
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
	if fqdn := svc.Annotations[AnnotationTailnetTargetFQDN]; fqdn != "" {
		svcSt.TailnetTarget = egressservices.TailnetTarget{FQDN: fqdn}
	}
	if ip := svc.Annotations[AnnotationTailnetTargetIP]; ip != "" {
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
			Labels:    pgLabels(pg, nil),
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
			Labels:    pgSecretLabels(pg, kubetypes.LabelSecretTypeState),
		},
	}
	return p, s
}

func randomPort() uint16 {
	return uint16(rand.Int32N(1000) + 1000)
}
