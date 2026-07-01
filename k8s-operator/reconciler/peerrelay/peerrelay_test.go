// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay_test

import (
	"fmt"
	"slices"
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/peerrelay"
)

const tailscaleNamespace = "tailscale"

// expectedService describes a Service the reconciler is expected to leave in the cluster. Every named Service must
// exist after reconcile; the optional fields (Type, Port, Protocol, Selector, Labels, Annotations) are checked only
// when non-zero. Labels/Annotations are matched as subsets — extra keys on the actual Service are allowed.
type expectedService struct {
	Name        string
	Type        corev1.ServiceType
	Port        int32
	Protocol    corev1.Protocol
	Selector    map[string]string
	Labels      map[string]string
	Annotations map[string]string
}

func TestReconciler_Reconcile(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		Name                string
		Request             reconcile.Request
		PeerRelay           *tsapi.PeerRelay
		ExistingResources   []client.Object
		ExpectsError        bool
		ExpectedServices    []expectedService
		ExpectedEndpoints   []tsapi.PeerRelayEndpoint
		ExpectedReadyStatus metav1.ConditionStatus // asserted only when non-empty
		ExpectFinalizer     bool
		ExpectPRDeleted     bool
	}{
		{
			Name:    "ignores-unknown-peer-relay",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "missing"}},
		},
		{
			Name:    "default-replicas",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			ExpectedServices: []expectedService{
				{
					Name:     "test-0",
					Type:     corev1.ServiceTypeLoadBalancer,
					Port:     41641,
					Protocol: corev1.ProtocolUDP,
					Selector: map[string]string{"statefulset.kubernetes.io/pod-name": "test-0"},
					Labels: map[string]string{
						"tailscale.com/managed":              "true",
						"tailscale.com/parent-resource-type": "peerrelay",
						"tailscale.com/parent-resource":      "test",
						"tailscale.com/peer-relay-replica":   "0",
					},
					Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
						"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
						"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internet-facing",
						"service.beta.kubernetes.io/aws-load-balancer-ip-address-type": "ipv4",
						"service.beta.kubernetes.io/azure-load-balancer-internal":      "false",
					},
				},
			},
			ExpectFinalizer: true,
		},
		{
			Name:    "multiple-replicas",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(3))},
			},
			ExpectedServices: []expectedService{
				{Name: "test-0", Labels: map[string]string{"tailscale.com/peer-relay-replica": "0"}},
				{Name: "test-1", Labels: map[string]string{"tailscale.com/peer-relay-replica": "1"}},
				{Name: "test-2", Labels: map[string]string{"tailscale.com/peer-relay-replica": "2"}},
			},
		},
		{
			Name:    "zero-replicas",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(0))},
			},
		},
		{
			Name:    "scale-down",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(2))},
			},
			ExistingResources: []client.Object{
				managedService("test", 0),
				managedService("test", 1),
				managedService("test", 2),
				managedService("test", 3),
			},
			ExpectedServices: []expectedService{
				{Name: "test-0"},
				{Name: "test-1"},
			},
		},
		{
			Name:    "scale-up",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(3))},
			},
			ExistingResources: []client.Object{
				managedService("test", 0),
			},
			ExpectedServices: []expectedService{
				{Name: "test-0"},
				{Name: "test-1"},
				{Name: "test-2"},
			},
		},
		{
			Name:    "scoped",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(1))},
			},
			ExistingResources: []client.Object{
				// A Service belonging to a different PeerRelay must not be touched.
				managedService("other", 5),
			},
			ExpectedServices: []expectedService{
				{Name: "other-5"},
				{Name: "test-0"},
			},
		},
		{
			Name:    "user-annotations",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Service: &tsapi.PeerRelayService{Annotations: map[string]string{"example.com/custom": "value"}},
				},
			},
			ExpectedServices: []expectedService{
				{
					Name: "test-0",
					Annotations: map[string]string{
						"example.com/custom": "value",
						"service.beta.kubernetes.io/aws-load-balancer-type":       "external",
						"service.beta.kubernetes.io/aws-load-balancer-scheme":     "internet-facing",
						"service.beta.kubernetes.io/azure-load-balancer-internal": "false",
					},
				},
			},
		},
		{
			Name:    "cloud-annotations",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Service: &tsapi.PeerRelayService{Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-scheme":     "internal",
						"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
					}},
				},
			},
			ExpectedServices: []expectedService{
				{
					Name: "test-0",
					Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-scheme":     "internet-facing",
						"service.beta.kubernetes.io/azure-load-balancer-internal": "false",
					},
				},
			},
		},
		{
			Name:    "drift-corrected",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(1))},
			},
			ExistingResources: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-0",
						Namespace: tailscaleNamespace,
						Labels: map[string]string{
							"tailscale.com/managed":              "true",
							"tailscale.com/parent-resource-type": "peerrelay",
							"tailscale.com/parent-resource":      "test",
							"tailscale.com/peer-relay-replica":   "0",
						},
						Annotations: map[string]string{
							"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
						},
					},
					Spec: corev1.ServiceSpec{
						Type: corev1.ServiceTypeClusterIP,
						Ports: []corev1.ServicePort{
							{Name: "wrong", Protocol: corev1.ProtocolTCP, Port: 80},
						},
					},
				},
			},
			ExpectedServices: []expectedService{
				{
					Name:     "test-0",
					Type:     corev1.ServiceTypeLoadBalancer,
					Port:     41641,
					Protocol: corev1.ProtocolUDP,
					Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing",
					},
				},
			},
		},
		{
			// GCP/Azure-style: the LB reports a plain IPv4 address; we surface it verbatim in status.endpoints.
			Name:    "endpoints-populated-from-lb-ip",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(2))},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "1.2.3.4", ""),
				managedServiceWithLB("test", 1, "5.6.7.8", ""),
			},
			ExpectedServices: []expectedService{{Name: "test-0"}, {Name: "test-1"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
				{Replica: 1, Address: "5.6.7.8", Port: 41641},
			},
		},
		{
			// Peer relays advertise a raw IP:port to peers, so a hostname-only LB (a misconfigured AWS NLB, for
			// example) must be rejected outright — no fallback. The reconciler surfaces this as an error and
			// leaves that replica out of status.endpoints.
			Name:    "hostname-only-lb-produces-error",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "", "test-0.elb.amazonaws.com"),
			},
			ExpectedServices:    []expectedService{{Name: "test-0"}},
			ExpectedEndpoints:   nil,
			ExpectsError:        true,
			ExpectedReadyStatus: metav1.ConditionFalse,
		},
		{
			// Mixed batch: one replica has a proper IP, another has only a hostname. The IP-provisioned replica
			// still shows up in status; the hostname-only one is skipped and drives the error.
			Name:    "mixed-ip-and-hostname-partial-status-plus-error",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(2))},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "1.2.3.4", ""),
				managedServiceWithLB("test", 1, "", "test-1.elb.amazonaws.com"),
			},
			ExpectedServices: []expectedService{{Name: "test-0"}, {Name: "test-1"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
			},
			ExpectsError:        true,
			ExpectedReadyStatus: metav1.ConditionFalse,
		},
		{
			// Mid-provisioning: some LBs have addresses, some don't yet. Only the ready ones show up.
			Name:    "endpoints-partial-when-lb-not-ready",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(3))},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "1.2.3.4", ""),
				managedService("test", 2),
			},
			ExpectedServices: []expectedService{{Name: "test-0"}, {Name: "test-1"}, {Name: "test-2"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
			},
		},
		{
			Name:    "deletion",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test",
					Finalizers:        []string{"tailscale.com/finalizer"},
					DeletionTimestamp: new(metav1.Now()),
				},
				Spec: tsapi.PeerRelaySpec{Replicas: new(int32(2))},
			},
			ExistingResources: []client.Object{
				managedService("test", 0),
				managedService("test", 1),
				managedService("other", 0),
			},
			ExpectedServices: []expectedService{{Name: "other-0"}},
			ExpectPRDeleted:  true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			builder := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme).
				WithStatusSubresource(&tsapi.PeerRelay{})
			if tc.PeerRelay != nil {
				builder = builder.WithObjects(tc.PeerRelay)
			}
			builder = builder.WithObjects(tc.ExistingResources...)

			fc := builder.Build()
			r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
				Client:             fc,
				TailscaleNamespace: tailscaleNamespace,
				Logger:             logger.Sugar(),
			})

			_, err = r.Reconcile(t.Context(), tc.Request)
			if tc.ExpectsError && err == nil {
				t.Fatalf("expected error, got none")
			}
			if !tc.ExpectsError && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			var svcs corev1.ServiceList
			if err = fc.List(t.Context(), &svcs, client.InNamespace(tailscaleNamespace)); err != nil {
				t.Fatal(err)
			}

			gotByName := make(map[string]corev1.Service, len(svcs.Items))
			gotNames := make([]string, 0, len(svcs.Items))
			for _, svc := range svcs.Items {
				gotByName[svc.Name] = svc
				gotNames = append(gotNames, svc.Name)
			}

			wantNames := make([]string, 0, len(tc.ExpectedServices))
			for _, want := range tc.ExpectedServices {
				wantNames = append(wantNames, want.Name)
			}

			slices.Sort(gotNames)
			slices.Sort(wantNames)
			if !slices.Equal(gotNames, wantNames) {
				t.Fatalf("expected services %v, got %v", wantNames, gotNames)
			}

			for _, want := range tc.ExpectedServices {
				assertService(t, want, new(gotByName[want.Name]))
			}

			if tc.PeerRelay == nil {
				return
			}

			var pr tsapi.PeerRelay
			err = fc.Get(t.Context(), types.NamespacedName{Name: tc.PeerRelay.Name}, &pr)
			switch {
			case tc.ExpectPRDeleted:
				if !apierrors.IsNotFound(err) {
					t.Fatalf("expected PeerRelay to be gone, got %v", err)
				}
			case err != nil:
				t.Fatalf("failed to refetch PeerRelay: %v", err)
			case tc.ExpectFinalizer:
				if !slices.Contains(pr.Finalizers, "tailscale.com/finalizer") {
					t.Errorf("expected finalizer to be set, got %v", pr.Finalizers)
				}
			}

			if !slices.Equal(pr.Status.Endpoints, tc.ExpectedEndpoints) {
				t.Errorf("expected status.endpoints %v, got %v", tc.ExpectedEndpoints, pr.Status.Endpoints)
			}

			if tc.ExpectedReadyStatus != "" {
				got := readyConditionStatus(&pr)
				if got != tc.ExpectedReadyStatus {
					t.Errorf("expected PeerRelayReady=%s, got %q", tc.ExpectedReadyStatus, got)
				}
			}
		})
	}
}

// readyConditionStatus returns the current status of the PeerRelayReady condition, or the empty string if unset.
func readyConditionStatus(pr *tsapi.PeerRelay) metav1.ConditionStatus {
	for _, cond := range pr.Status.Conditions {
		if cond.Type == string(tsapi.PeerRelayReady) {
			return cond.Status
		}
	}
	return ""
}

func assertService(t *testing.T, want expectedService, got *corev1.Service) {
	t.Helper()

	if want.Type != "" && got.Spec.Type != want.Type {
		t.Errorf("Service %q: expected type %q, got %q", want.Name, want.Type, got.Spec.Type)
	}

	if want.Port != 0 || want.Protocol != "" {
		if len(got.Spec.Ports) != 1 {
			t.Fatalf("Service %q: expected exactly one port, got %d", want.Name, len(got.Spec.Ports))
		}
		if want.Protocol != "" && got.Spec.Ports[0].Protocol != want.Protocol {
			t.Errorf("Service %q: expected protocol %q, got %q", want.Name, want.Protocol, got.Spec.Ports[0].Protocol)
		}
		if want.Port != 0 && got.Spec.Ports[0].Port != want.Port {
			t.Errorf("Service %q: expected port %d, got %d", want.Name, want.Port, got.Spec.Ports[0].Port)
		}
	}

	for k, v := range want.Selector {
		if gotV := got.Spec.Selector[k]; gotV != v {
			t.Errorf("Service %q: expected selector %q=%q, got %q", want.Name, k, v, gotV)
		}
	}

	for k, v := range want.Labels {
		if gotV := got.Labels[k]; gotV != v {
			t.Errorf("Service %q: expected label %q=%q, got %q", want.Name, k, v, gotV)
		}
	}

	for k, v := range want.Annotations {
		if gotV := got.Annotations[k]; gotV != v {
			t.Errorf("Service %q: expected annotation %q=%q, got %q", want.Name, k, v, gotV)
		}
	}
}

// managedService returns a minimally-populated Service that looks like one the reconciler would have created for
// the given PeerRelay and replica index. Used to seed pre-existing state for scale-down and delete cases.
func managedService(prName string, idx int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d", prName, idx),
			Namespace: tailscaleNamespace,
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource-type": "peerrelay",
				"tailscale.com/parent-resource":      prName,
				"tailscale.com/peer-relay-replica":   fmt.Sprintf("%d", idx),
			},
		},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer},
	}
}

func managedServiceWithLB(prName string, idx int, ip, hostname string) *corev1.Service {
	svc := managedService(prName, idx)
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: ip, Hostname: hostname}}
	return svc
}
