// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
)

func TestEgressPodReadiness(t *testing.T) {
	const podUID = "pod-uid"
	tests := []struct {
		name      string
		objs      []client.Object
		podIPs    []string               // defaults to dual-stack
		status    *egressservices.Status // defaults to a status for podIPs
		wantReady bool
	}{
		{
			name:      "no_egress_services",
			wantReady: true,
		},
		{
			name: "pod_is_endpoint_for_all_services",
			objs: []client.Object{
				newSvc("svc"), newEps("svc", discoveryv1.AddressTypeIPv4, podUID),
				newSvc("svc-2"), newEps("svc-2", discoveryv1.AddressTypeIPv4, "other-uid", podUID),
			},
			wantReady: true,
		},
		{
			name: "pod_is_endpoint_in_both_families",
			objs: []client.Object{
				newSvc("svc"),
				newEps("svc", discoveryv1.AddressTypeIPv4, podUID),
				newEps("svc", discoveryv1.AddressTypeIPv6, podUID),
			},
			wantReady: true,
		},
		{
			name: "pod_is_endpoint_in_one_family_only",
			objs: []client.Object{
				newSvc("svc"),
				newEps("svc", discoveryv1.AddressTypeIPv4),
				newEps("svc", discoveryv1.AddressTypeIPv6, podUID),
			},
		},
		{
			name: "single_stack_pod_is_endpoint_in_its_family",
			objs: []client.Object{
				newSvc("svc"),
				newEps("svc", discoveryv1.AddressTypeIPv4, podUID),
				newEps("svc", discoveryv1.AddressTypeIPv6),
			},
			podIPs:    []string{"10.0.0.2"},
			wantReady: true,
		},
		{
			name: "single_stack_pod_is_not_endpoint_in_its_family",
			objs: []client.Object{
				newSvc("svc"),
				newEps("svc", discoveryv1.AddressTypeIPv4),
				newEps("svc", discoveryv1.AddressTypeIPv6),
			},
			podIPs: []string{"fd00::2"},
		},
		{
			// A proxy older than v1.102 reports only PodIPv4, so egress-eps-reconciler never adds it to the IPv6
			// EndpointSlice.
			name: "dual_stack_pod_proxy_reports_ipv4_only",
			objs: []client.Object{
				newSvc("svc"),
				newEps("svc", discoveryv1.AddressTypeIPv4, podUID),
				newEps("svc", discoveryv1.AddressTypeIPv6),
			},
			status:    &egressservices.Status{PodIPv4: "10.0.0.2"},
			wantReady: true,
		},
		{
			name: "pod_is_not_endpoint_for_one_service",
			objs: []client.Object{
				newSvc("svc"), newEps("svc", discoveryv1.AddressTypeIPv4, podUID),
				newSvc("svc-2"), newEps("svc-2", discoveryv1.AddressTypeIPv4, "other-uid"),
			},
		},
		{
			name: "service_has_no_endpointslice_yet",
			objs: []client.Object{newSvc("svc")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			podIPs := tt.podIPs
			if podIPs == nil {
				podIPs = []string{"10.0.0.2", "fd00::2"}
			}
			status := tt.status
			if status == nil {
				status = &egressservices.Status{}
				for _, ip := range podIPs {
					if netip.MustParseAddr(ip).Is4() {
						status.PodIPv4 = ip
					} else {
						status.PodIPv6 = ip
					}
				}
			}
			statusBS, err := json.Marshal(status)
			if err != nil {
				t.Fatal(err)
			}
			stateS := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "operator-ns",
					Name:      "pod",
				},
				Data: map[string][]byte{egressservices.KeyEgressServices: statusBS},
			}
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "operator-ns",
					Name:      "pod",
					UID:       podUID,
					Labels: map[string]string{
						LabelParentType: "proxygroup",
						LabelParentName: "dev",
					},
				},
				Spec: corev1.PodSpec{
					ReadinessGates: []corev1.PodReadinessGate{{
						ConditionType: tsEgressReadinessGate,
					}},
				},
			}
			for _, ip := range podIPs {
				pod.Status.PodIPs = append(pod.Status.PodIPs, corev1.PodIP{IP: ip})
			}
			pg := &tsapi.ProxyGroup{
				ObjectMeta: metav1.ObjectMeta{Name: "dev"},
				Spec: tsapi.ProxyGroupSpec{
					Type:     "egress",
					Replicas: new(int32(3)),
				},
			}
			// We need to pass a Pod object to WithStatusSubresource because of some quirks in how the fake client
			// works. Without this code we would not be able to update Pod's status further down.
			fc := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme).
				WithObjects(append(tt.objs, pod, pg, stateS)...).
				WithStatusSubresource(&corev1.Pod{}).
				Build()
			zl, _ := zap.NewDevelopment()
			cl := tstest.NewClock(tstest.ClockOpts{})
			rec := &egressPodsReconciler{
				tsNamespace: "operator-ns",
				Client:      fc,
				logger:      zl.Sugar(),
				clock:       cl,
			}

			if !tt.wantReady {
				expectRequeue(t, rec, "operator-ns", pod.Name)
				expectEqual(t, fc, pod)
				return
			}
			expectReconciled(t, rec, "operator-ns", pod.Name)
			pod.Status.Conditions = append(pod.Status.Conditions, corev1.PodCondition{
				Type:               tsEgressReadinessGate,
				Status:             corev1.ConditionTrue,
				LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
			})
			expectEqual(t, fc, pod)

			// A subsequent reconcile should not change the Pod.
			expectReconciled(t, rec, "operator-ns", pod.Name)
			expectEqual(t, fc, pod)
		})
	}
}

// newSvc returns an egress ClusterIP Service for the "dev" ProxyGroup.
func newSvc(name string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "operator-ns",
			Name:      name,
			Labels:    egressLabels(),
		},
	}
}

// newEps returns an EndpointSlice for the given egress ClusterIP Service with an endpoint for each of the given
// Pod UIDs, as egress-eps-reconciler would create it.
func newEps(svcName string, addrType discoveryv1.AddressType, podUIDs ...string) *discoveryv1.EndpointSlice {
	lbls := egressLabels()
	lbls[discoveryv1.LabelServiceName] = svcName
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "operator-ns",
			Name:      svcName + "-" + string(addrType),
			Labels:    lbls,
		},
		AddressType: addrType,
	}
	for _, uid := range podUIDs {
		eps.Endpoints = append(eps.Endpoints, discoveryv1.Endpoint{
			Hostname:  new(uid),
			Addresses: []string{"10.0.0.2"},
		})
	}
	return eps
}

// egressLabels returns the labels that the operator sets on egress ClusterIP Services and EndpointSlices for the
// "dev" ProxyGroup.
func egressLabels() map[string]string {
	return map[string]string{
		kubetypes.LabelManaged: "true",
		labelProxyGroup:        "dev",
		labelSvcType:           typeEgress,
	}
}
