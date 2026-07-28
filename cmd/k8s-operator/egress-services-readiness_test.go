// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"fmt"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
)

func TestEgressServiceReadiness(t *testing.T) {
	// We need to pass a ProxyGroup object to WithStatusSubresource because of some quirks in how the fake client
	// works. Without this code further down would not be able to update ProxyGroup status.
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.ProxyGroup{}).
		Build()
	zl, _ := zap.NewDevelopment()
	cl := tstest.NewClock(tstest.ClockOpts{})
	rec := &egressSvcsReadinessReconciler{
		tsNamespace: "operator-ns",
		Client:      fc,
		logger:      zl.Sugar(),
		clock:       cl,
	}
	tailnetFQDN := "my-app.tailnetxyz.ts.net"
	egressSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "dev",
			Annotations: map[string]string{
				AnnotationProxyGroup:        "dev",
				AnnotationTailnetTargetFQDN: tailnetFQDN,
			},
		},
	}
	fakeClusterIPSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "operator-ns",
			Labels:    egressSvcChildResourceLabels(egressSvc),
		},
		Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.0.0.1"}},
	}
	labels := egressSvcEpsLabels(egressSvc, fakeClusterIPSvc)
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "operator-ns",
			Labels:    labels,
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dev",
		},
	}
	mustCreate(t, fc, egressSvc)
	mustCreate(t, fc, fakeClusterIPSvc)
	setClusterNotReady(egressSvc, cl, zl.Sugar())
	t.Run("endpointslice_does_not_exist", func(t *testing.T) {
		expectReconciled(t, rec, "dev", "my-app")
		expectEqual(t, fc, egressSvc) // not ready
	})
	t.Run("proxy_group_does_not_exist", func(t *testing.T) {
		mustCreate(t, fc, eps)
		expectReconciled(t, rec, "dev", "my-app")
		expectEqual(t, fc, egressSvc) // still not ready
	})
	t.Run("proxy_group_not_ready", func(t *testing.T) {
		mustCreate(t, fc, pg)
		expectReconciled(t, rec, "dev", "my-app")
		expectEqual(t, fc, egressSvc) // still not ready
	})
	t.Run("no_ready_replicas", func(t *testing.T) {
		setPGReady(pg, cl, zl.Sugar())
		mustUpdateStatus(t, fc, pg.Namespace, pg.Name, func(p *tsapi.ProxyGroup) {
			p.Status = pg.Status
		})
		expectEqual(t, fc, pg)
		for i := range pgReplicas(pg) {
			p := pod(pg, i)
			mustCreate(t, fc, p)
			mustUpdateStatus(t, fc, p.Namespace, p.Name, func(existing *corev1.Pod) {
				existing.Status.PodIPs = p.Status.PodIPs
			})
		}
		expectReconciled(t, rec, "dev", "my-app")
		setNotReady(egressSvc, cl, zl.Sugar(), pgReplicas(pg))
		expectEqual(t, fc, egressSvc) // still not ready
	})
	t.Run("one_ready_replica", func(t *testing.T) {
		setEndpointForReplica(pg, 0, eps)
		mustUpdate(t, fc, eps.Namespace, eps.Name, func(e *discoveryv1.EndpointSlice) {
			e.Endpoints = eps.Endpoints
		})
		setReady(egressSvc, cl, zl.Sugar(), pgReplicas(pg), 1)
		expectReconciled(t, rec, "dev", "my-app")
		expectEqual(t, fc, egressSvc) // partially ready
	})
	t.Run("all_replicas_ready", func(t *testing.T) {
		for i := range pgReplicas(pg) {
			setEndpointForReplica(pg, i, eps)
		}
		mustUpdate(t, fc, eps.Namespace, eps.Name, func(e *discoveryv1.EndpointSlice) {
			e.Endpoints = eps.Endpoints
		})
		setReady(egressSvc, cl, zl.Sugar(), pgReplicas(pg), pgReplicas(pg))
		expectReconciled(t, rec, "dev", "my-app")
		expectEqual(t, fc, egressSvc) // ready
	})
}

func TestEgressServiceReadinessDualStack(t *testing.T) {
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.ProxyGroup{}).
		Build()
	zl, _ := zap.NewDevelopment()
	cl := tstest.NewClock(tstest.ClockOpts{})
	rec := &egressSvcsReadinessReconciler{
		tsNamespace: "operator-ns",
		Client:      fc,
		logger:      zl.Sugar(),
		clock:       cl,
	}
	tailnetFQDN := "my-app.tailnetxyz.ts.net"
	egressSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "dev",
			Annotations: map[string]string{
				AnnotationProxyGroup:        "dev",
				AnnotationTailnetTargetFQDN: tailnetFQDN,
			},
		},
	}
	fakeClusterIPSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "operator-ns",
			Labels:    egressSvcChildResourceLabels(egressSvc),
		},
		Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.0.0.1", "fd00::1"}},
	}
	labels := egressSvcEpsLabels(egressSvc, fakeClusterIPSvc)
	epsV4 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app-ipv4",
			Namespace: "operator-ns",
			Labels:    labels,
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}
	labelsV6 := egressSvcEpsLabels(egressSvc, fakeClusterIPSvc)
	epsV6 := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app-ipv6",
			Namespace: "operator-ns",
			Labels:    labelsV6,
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dev",
		},
		Spec: tsapi.ProxyGroupSpec{
			Replicas: new(int32(1)),
			Type:     tsapi.ProxyGroupTypeEgress,
		},
	}
	mustCreate(t, fc, egressSvc)
	mustCreate(t, fc, fakeClusterIPSvc)
	mustCreate(t, fc, epsV4)
	mustCreate(t, fc, epsV6)
	mustCreate(t, fc, pg)
	setPGReady(pg, cl, zl.Sugar())
	mustUpdateStatus(t, fc, pg.Namespace, pg.Name, func(p *tsapi.ProxyGroup) {
		p.Status = pg.Status
	})

	// Create a dual-stack pod.
	p := pod(pg, 0)
	p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: "fd00::0"})
	mustCreate(t, fc, p)
	mustUpdateStatus(t, fc, p.Namespace, p.Name, func(existing *corev1.Pod) {
		existing.Status.PodIPs = p.Status.PodIPs
	})

	t.Run("not_ready_missing_from_ipv6_slice", func(t *testing.T) {
		setEndpointForReplicaWithIP("10.0.0.0", epsV4)
		mustUpdate(t, fc, epsV4.Namespace, epsV4.Name, func(e *discoveryv1.EndpointSlice) {
			e.Endpoints = epsV4.Endpoints
		})
		expectReconciled(t, rec, "dev", "my-app")
		setNotReady(egressSvc, cl, zl.Sugar(), pgReplicas(pg))
		expectEqual(t, fc, egressSvc)
	})
	t.Run("ready_in_both_slices", func(t *testing.T) {
		setEndpointForReplicaWithIP("fd00::", epsV6)
		mustUpdate(t, fc, epsV6.Namespace, epsV6.Name, func(e *discoveryv1.EndpointSlice) {
			e.Endpoints = epsV6.Endpoints
		})
		expectReconciled(t, rec, "dev", "my-app")
		setReady(egressSvc, cl, zl.Sugar(), pgReplicas(pg), pgReplicas(pg))
		expectEqual(t, fc, egressSvc)
	})
	t.Run("not_ready_when_ipv6_slice_missing", func(t *testing.T) {
		// Delete the IPv6 EndpointSlice while the ClusterIP Service still
		// wants an IPv6 family; the Service should report NotReady even though
		// the IPv4 EndpointSlice is healthy.
		if err := fc.Delete(t.Context(), epsV6); err != nil {
			t.Fatalf("error deleting IPv6 EndpointSlice: %v", err)
		}
		expectReconciled(t, rec, "dev", "my-app")
		setClusterNotReady(egressSvc, cl, zl.Sugar())
		expectEqual(t, fc, egressSvc)
	})
}

func TestEgressServiceReadinessIPv6Only(t *testing.T) {
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.ProxyGroup{}).
		Build()
	zl, _ := zap.NewDevelopment()
	cl := tstest.NewClock(tstest.ClockOpts{})
	rec := &egressSvcsReadinessReconciler{
		tsNamespace: "operator-ns",
		Client:      fc,
		logger:      zl.Sugar(),
		clock:       cl,
	}
	egressSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "dev",
			Annotations: map[string]string{
				AnnotationProxyGroup:        "dev",
				AnnotationTailnetTargetFQDN: "my-app.tailnetxyz.ts.net",
			},
		},
	}
	fakeClusterIPSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app",
			Namespace: "operator-ns",
			Labels:    egressSvcChildResourceLabels(egressSvc),
		},
		Spec: corev1.ServiceSpec{ClusterIPs: []string{"fd00::1"}},
	}
	labels := egressSvcEpsLabels(egressSvc, fakeClusterIPSvc)
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-app-ipv6",
			Namespace: "operator-ns",
			Labels:    labels,
		},
		AddressType: discoveryv1.AddressTypeIPv6,
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dev",
		},
	}
	mustCreate(t, fc, egressSvc)
	mustCreate(t, fc, fakeClusterIPSvc)
	mustCreate(t, fc, eps)
	mustCreate(t, fc, pg)
	setPGReady(pg, cl, zl.Sugar())
	mustUpdateStatus(t, fc, pg.Namespace, pg.Name, func(p *tsapi.ProxyGroup) {
		p.Status = pg.Status
	})

	// Create IPv6-only pods.
	for i := range pgReplicas(pg) {
		p := ipv6OnlyPod(pg, i)
		mustCreate(t, fc, p)
		mustUpdateStatus(t, fc, p.Namespace, p.Name, func(existing *corev1.Pod) {
			existing.Status.PodIPs = p.Status.PodIPs
		})
	}

	t.Run("no_ready_replicas", func(t *testing.T) {
		expectReconciled(t, rec, "dev", "my-app")
		setNotReady(egressSvc, cl, zl.Sugar(), pgReplicas(pg))
		expectEqual(t, fc, egressSvc)
	})
	t.Run("all_replicas_ready", func(t *testing.T) {
		for i := range pgReplicas(pg) {
			p := ipv6OnlyPod(pg, i)
			setEndpointForReplicaWithIP(p.Status.PodIPs[0].IP, eps)
		}
		mustUpdate(t, fc, eps.Namespace, eps.Name, func(e *discoveryv1.EndpointSlice) {
			e.Endpoints = eps.Endpoints
		})
		setReady(egressSvc, cl, zl.Sugar(), pgReplicas(pg), pgReplicas(pg))
		expectReconciled(t, rec, "dev", "my-app")
		expectEqual(t, fc, egressSvc)
	})
}

func ipv6OnlyPod(pg *tsapi.ProxyGroup, ordinal int32) *corev1.Pod {
	labels := pgLabels(pg.Name, nil)
	labels[appsv1.PodIndexLabel] = fmt.Sprintf("%d", ordinal)
	ip := fmt.Sprintf("fd00::%d", ordinal+1) // +1 to avoid fd00::0 normalization issues
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d", pg.Name, ordinal),
			Namespace: "operator-ns",
			Labels:    labels,
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: ip}},
		},
	}
}

func setClusterNotReady(svc *corev1.Service, cl tstime.Clock, lg *zap.SugaredLogger) {
	tsoperator.SetServiceCondition(svc, tsapi.EgressSvcReady, metav1.ConditionFalse, reasonClusterResourcesNotReady, reasonClusterResourcesNotReady, cl, lg)
}

func setNotReady(svc *corev1.Service, cl tstime.Clock, lg *zap.SugaredLogger, replicas int32) {
	msg := fmt.Sprintf(msgReadyToRouteTemplate, 0, replicas)
	tsoperator.SetServiceCondition(svc, tsapi.EgressSvcReady, metav1.ConditionFalse, reasonNotReady, msg, cl, lg)
}

func setReady(svc *corev1.Service, cl tstime.Clock, lg *zap.SugaredLogger, replicas, readyReplicas int32) {
	reason := reasonPartiallyReady
	if readyReplicas == replicas {
		reason = reasonReady
	}
	msg := fmt.Sprintf(msgReadyToRouteTemplate, readyReplicas, replicas)
	tsoperator.SetServiceCondition(svc, tsapi.EgressSvcReady, metav1.ConditionTrue, reason, msg, cl, lg)
}

func setPGReady(pg *tsapi.ProxyGroup, cl tstime.Clock, lg *zap.SugaredLogger) {
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, "foo", "foo", pg.Generation, cl, lg)
}

func setEndpointForReplica(pg *tsapi.ProxyGroup, ordinal int32, eps *discoveryv1.EndpointSlice) {
	p := pod(pg, ordinal)
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses: []string{p.Status.PodIPs[0].IP},
		Conditions: discoveryv1.EndpointConditions{
			Ready:       new(true),
			Serving:     new(true),
			Terminating: new(false),
		},
	})
}

func pod(pg *tsapi.ProxyGroup, ordinal int32) *corev1.Pod {
	labels := pgLabels(pg.Name, nil)
	labels[appsv1.PodIndexLabel] = fmt.Sprintf("%d", ordinal)
	ip := fmt.Sprintf("10.0.0.%d", ordinal)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d", pg.Name, ordinal),
			Namespace: "operator-ns",
			Labels:    labels,
		},
		Status: corev1.PodStatus{
			PodIPs: []corev1.PodIP{{IP: ip}},
		},
	}
}

func setEndpointForReplicaWithIP(ip string, eps *discoveryv1.EndpointSlice) {
	eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
		Addresses: []string{ip},
		Conditions: discoveryv1.EndpointConditions{
			Ready:       new(true),
			Serving:     new(true),
			Terminating: new(false),
		},
	})
}
