// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

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
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(svc, cm).
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
			Labels: map[string]string{
				LabelParentName:      "test",
				LabelParentNamespace: "default",
				labelSvcType:         typeEgress,
				labelProxyGroup:      "foo"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	mustCreate(t, fc, eps)

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
			Labels: map[string]string{
				LabelParentName:      "test",
				LabelParentNamespace: "default",
				labelSvcType:         typeEgress,
				labelProxyGroup:      "foo",
			},
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	mustCreate(t, fc, epsV6)
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
