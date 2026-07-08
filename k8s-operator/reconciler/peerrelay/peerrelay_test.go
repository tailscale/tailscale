// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	tailscaleclient "tailscale.com/client/tailscale/v2"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/peerrelay"
	"tailscale.com/k8s-operator/tsclient"
)

const (
	tailscaleNamespace = "tailscale"
	testProxyImage     = "tailscale/tailscale:test"
)

type expectedService struct {
	Name        string
	Type        corev1.ServiceType
	Port        int32
	NodePort    int32
	Protocol    corev1.Protocol
	Selector    map[string]string
	Labels      map[string]string
	Annotations map[string]string
}

type statefulSetSpec struct {
	Replicas int32
	Image    string
}

func TestReconciler_Reconcile(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	tt := []struct {
		Name                  string
		Request               reconcile.Request
		PeerRelay             *tsapi.PeerRelay
		ExistingResources     []client.Object
		ExpectsError          bool
		ExpectedServices      []expectedService
		ExpectedEndpoints     []tsapi.PeerRelayEndpoint
		ExpectedReadyStatus   metav1.ConditionStatus // asserted only when non-empty
		ExpectedReadyReason   string                 // asserted only when non-empty
		ExpectStatefulSetGone bool                   // assert the StatefulSet does not exist
		ExpectStatefulSetSpec *statefulSetSpec       // asserted only when non-nil
		ExpectedConfigSecrets []string               // exact set of config Secret names expected; nil == skip check
		ExpectFinalizer       bool
		ExpectPRDeleted       bool
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
			ExpectFinalizer:       true,
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 1, Image: testProxyImage},
			ExpectedConfigSecrets: []string{"test-0-config"},
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
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 3, Image: testProxyImage},
			ExpectedConfigSecrets: []string{"test-0-config", "test-1-config", "test-2-config"},
		},
		{
			Name:    "zero-replicas",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(0))},
			},
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 0, Image: testProxyImage},
			ExpectedConfigSecrets: []string{},
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
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 2, Image: testProxyImage},
			ExpectedConfigSecrets: []string{"test-0-config", "test-1-config"},
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
							// External label added by some other controller; must survive.
							"cloud.google.com/backend-config": "attached",
						},
						Annotations: map[string]string{
							"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
							// External annotation the cloud LB controller stamps on the Service; must survive.
							"cloud.google.com/neg-status": `{"network_endpoint_groups": {}}`,
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
					Labels: map[string]string{
						"tailscale.com/managed":           "true",
						"cloud.google.com/backend-config": "attached", // external label preserved
					},
					Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing",                 // drift corrected
						"cloud.google.com/neg-status":                         `{"network_endpoint_groups": {}}`, // external annotation preserved
					},
				},
			},
		},
		{
			// The cloud LB controller writes its own annotations, kube-proxy assigns a NodePort, and both keep
			// updating the Service after we create it. Reconcile must not strip external metadata or the assigned
			// NodePort; if it does we ping-pong with the cloud provider forever.
			Name:    "preserves-external-additions-on-settled-service",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
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
							"cloud.google.com/backend-config":    "attached",
						},
						Annotations: map[string]string{
							"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
							"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
							"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internet-facing",
							"service.beta.kubernetes.io/aws-load-balancer-ip-address-type": "ipv4",
							"service.beta.kubernetes.io/azure-load-balancer-internal":      "false",
							"cloud.google.com/neg-status":                                  `{"zones": ["europe-west2-a"]}`,
						},
						ResourceVersion: "1",
					},
					Spec: corev1.ServiceSpec{
						Type: corev1.ServiceTypeLoadBalancer,
						Selector: map[string]string{
							"statefulset.kubernetes.io/pod-name": "test-0",
						},
						Ports: []corev1.ServicePort{
							{
								Name:       "peerrelay",
								Protocol:   corev1.ProtocolUDP,
								Port:       41641,
								TargetPort: intstr.FromInt32(41641),
								NodePort:   31545, // cluster-assigned; must survive.
							},
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
					NodePort: 31545,
					Labels: map[string]string{
						"cloud.google.com/backend-config": "attached",
					},
					Annotations: map[string]string{
						"cloud.google.com/neg-status": `{"zones": ["europe-west2-a"]}`,
					},
				},
			},
			// No LB ingress seeded, so status is still Pending — the point of this case is the *Service* is
			// unchanged, not the PR status.
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonEndpointsPending,
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
				// Seed a StatefulSet with both replicas Ready so the writeStatus precedence path can reach
				// ReasonReady. Without this the fake client's fresh StatefulSet would have ReadyReplicas=0 and
				// we'd land in PodsPending instead.
				managedStatefulSet("test", 2, 2),
			},
			ExpectedServices: []expectedService{{Name: "test-0"}, {Name: "test-1"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
				{Replica: 1, Address: "5.6.7.8", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionTrue,
			ExpectedReadyReason: peerrelay.ReasonReady,
		},
		{
			// All LB IPs assigned but pods haven't reported Ready yet
			Name:    "pods-pending-blocks-ready",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(2))},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "1.2.3.4", ""),
				managedServiceWithLB("test", 1, "5.6.7.8", ""),
				managedStatefulSet("test", 2, 1), // only 1 of 2 pods Ready
			},
			ExpectedServices: []expectedService{{Name: "test-0"}, {Name: "test-1"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
				{Replica: 1, Address: "5.6.7.8", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonPodsPending,
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
			ExpectedReadyReason: peerrelay.ReasonEndpointsInvalid,
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
			ExpectedReadyReason: peerrelay.ReasonEndpointsInvalid,
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
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonEndpointsPending,
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
				managedConfigSecret("test", 0),
				managedConfigSecret("test", 1),
				&appsv1.StatefulSet{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: tailscaleNamespace,
					},
				},
			},
			ExpectedServices:      []expectedService{{Name: "other-0"}},
			ExpectPRDeleted:       true,
			ExpectStatefulSetGone: true,
			ExpectedConfigSecrets: []string{},
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			builder := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme).
				WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{})
			if tc.PeerRelay != nil {
				builder = builder.WithObjects(tc.PeerRelay)
			}
			builder = builder.WithObjects(tc.ExistingResources...)

			fc := builder.Build()
			r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
				Client:             fc,
				TailscaleNamespace: tailscaleNamespace,
				ProxyImage:         testProxyImage,
				DefaultTags:        []string{"tag:test-peer-relay"},
				Clients:            &fakeClientProvider{client: &fakeTSClient{}},
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

			if tc.ExpectedReadyStatus != "" || tc.ExpectedReadyReason != "" {
				cond := readyCondition(&pr)
				if tc.ExpectedReadyStatus != "" && cond.Status != tc.ExpectedReadyStatus {
					t.Errorf("expected PeerRelayReady status %s, got %q", tc.ExpectedReadyStatus, cond.Status)
				}
				if tc.ExpectedReadyReason != "" && cond.Reason != tc.ExpectedReadyReason {
					t.Errorf("expected PeerRelayReady reason %s, got %q", tc.ExpectedReadyReason, cond.Reason)
				}
			}

			assertStatefulSet(t, fc, tc.Request.Name, tc.ExpectStatefulSetSpec, tc.ExpectStatefulSetGone)
			if tc.ExpectedConfigSecrets != nil {
				assertConfigSecrets(t, fc, tc.Request.Name, tc.ExpectedConfigSecrets)
			}
		})
	}
}

func assertStatefulSet(t *testing.T, fc client.Client, prName string, want *statefulSetSpec, gone bool) {
	t.Helper()

	var ss appsv1.StatefulSet
	err := fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: prName}, &ss)
	switch {
	case gone:
		if !apierrors.IsNotFound(err) {
			t.Errorf("expected StatefulSet %q to be absent, got err=%v", prName, err)
		}
		return
	case want == nil:
		return
	case err != nil:
		t.Fatalf("expected StatefulSet %q, got err %v", prName, err)
	}

	if ss.Spec.Replicas == nil || *ss.Spec.Replicas != want.Replicas {
		got := "<nil>"
		if ss.Spec.Replicas != nil {
			got = fmt.Sprintf("%d", *ss.Spec.Replicas)
		}
		t.Errorf("expected StatefulSet replicas=%d, got %s", want.Replicas, got)
	}

	if want.Image != "" {
		if len(ss.Spec.Template.Spec.Containers) == 0 {
			t.Fatalf("StatefulSet template has no containers")
		}
		if ss.Spec.Template.Spec.Containers[0].Image != want.Image {
			t.Errorf("expected container image %q, got %q", want.Image, ss.Spec.Template.Spec.Containers[0].Image)
		}
	}
}

func assertConfigSecrets(t *testing.T, fc client.Client, prName string, want []string) {
	t.Helper()

	var list corev1.SecretList
	if err := fc.List(t.Context(), &list, client.InNamespace(tailscaleNamespace), client.MatchingLabels(map[string]string{
		"tailscale.com/parent-resource-type": "peerrelay",
		"tailscale.com/parent-resource":      prName,
	})); err != nil {
		t.Fatal(err)
	}

	got := make([]string, 0, len(list.Items))
	for _, s := range list.Items {
		got = append(got, s.Name)
	}

	slices.Sort(got)
	sortedWant := slices.Clone(want)
	slices.Sort(sortedWant)

	if !slices.Equal(got, sortedWant) {
		t.Errorf("expected config Secrets %v, got %v", sortedWant, got)
	}
}

func readyCondition(pr *tsapi.PeerRelay) metav1.Condition {
	for _, cond := range pr.Status.Conditions {
		if cond.Type == string(tsapi.PeerRelayReady) {
			return cond
		}
	}

	return metav1.Condition{}
}

func assertService(t *testing.T, want expectedService, got *corev1.Service) {
	t.Helper()

	if want.Type != "" && got.Spec.Type != want.Type {
		t.Errorf("Service %q: expected type %q, got %q", want.Name, want.Type, got.Spec.Type)
	}

	if want.Port != 0 || want.Protocol != "" || want.NodePort != 0 {
		if len(got.Spec.Ports) != 1 {
			t.Fatalf("Service %q: expected exactly one port, got %d", want.Name, len(got.Spec.Ports))
		}
		if want.Protocol != "" && got.Spec.Ports[0].Protocol != want.Protocol {
			t.Errorf("Service %q: expected protocol %q, got %q", want.Name, want.Protocol, got.Spec.Ports[0].Protocol)
		}
		if want.Port != 0 && got.Spec.Ports[0].Port != want.Port {
			t.Errorf("Service %q: expected port %d, got %d", want.Name, want.Port, got.Spec.Ports[0].Port)
		}
		if want.NodePort != 0 && got.Spec.Ports[0].NodePort != want.NodePort {
			t.Errorf("Service %q: expected nodePort %d, got %d", want.Name, want.NodePort, got.Spec.Ports[0].NodePort)
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

func managedStatefulSet(prName string, replicas, ready int32) *appsv1.StatefulSet {
	labels := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource-type": "peerrelay",
		"tailscale.com/parent-resource":      prName,
	}
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      prName,
			Namespace: tailscaleNamespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			ServiceName: prName,
			Selector:    &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{},
			},
		},
		Status: appsv1.StatefulSetStatus{ReadyReplicas: ready},
	}
}

func managedConfigSecret(prName string, idx int) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-%d-config", prName, idx),
			Namespace: tailscaleNamespace,
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource-type": "peerrelay",
				"tailscale.com/parent-resource":      prName,
				"tailscale.com/peer-relay-replica":   fmt.Sprintf("%d", idx),
			},
		},
	}
}

func TestReconciler_TailscaledConfig(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(2))},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.PeerRelay{}).
		WithObjects(
			pr,
			managedServiceWithLB("test", 0, "1.2.3.4", ""),
			managedService("test", 1),
		).
		Build()

	r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: tailscaleNamespace,
		ProxyImage:         testProxyImage,
		DefaultTags:        []string{"tag:test-peer-relay"},
		Clients:            &fakeClientProvider{client: &fakeTSClient{}},
		Logger:             logger.Sugar(),
	})

	if _, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
		t.Fatal(err)
	}

	got0 := readTailscaledConfig(t, fc, "test-0-config")
	if got0.RelayServerPort == nil || *got0.RelayServerPort != 41641 {
		t.Errorf("replica 0: expected RelayServerPort=41641, got %v", got0.RelayServerPort)
	}
	wantEndpoints := []netip.AddrPort{netip.MustParseAddrPort("1.2.3.4:41641")}
	if !slices.Equal(got0.RelayServerStaticEndpoints, wantEndpoints) {
		t.Errorf("replica 0: expected RelayServerStaticEndpoints=%v, got %v", wantEndpoints, got0.RelayServerStaticEndpoints)
	}
	if got0.Hostname == nil || *got0.Hostname != "test-0" {
		t.Errorf("replica 0: expected hostname=test-0, got %v", got0.Hostname)
	}

	got1 := readTailscaledConfig(t, fc, "test-1-config")
	if got1.RelayServerPort == nil || *got1.RelayServerPort != 41641 {
		t.Errorf("replica 1: expected RelayServerPort=41641, got %v", got1.RelayServerPort)
	}
	// Replica 1's LB has not been provisioned yet, so no static endpoints.
	if len(got1.RelayServerStaticEndpoints) != 0 {
		t.Errorf("replica 1: expected no RelayServerStaticEndpoints, got %v", got1.RelayServerStaticEndpoints)
	}
}

func readTailscaledConfig(t *testing.T, fc client.Client, secretName string) ipn.ConfigVAlpha {
	t.Helper()

	var secret corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: secretName}, &secret); err != nil {
		t.Fatalf("failed to get config Secret %q: %v", secretName, err)
	}

	if len(secret.Data) != 1 {
		t.Fatalf("expected exactly one file in config Secret %q, got %d", secretName, len(secret.Data))
	}

	var conf ipn.ConfigVAlpha
	for name, body := range secret.Data {
		if err := json.Unmarshal(body, &conf); err != nil {
			t.Fatalf("failed to unmarshal config file %q from Secret %q: %v", name, secretName, err)
		}
	}

	return conf
}

// fakeClientProvider is a peerrelay.ClientProvider that ignores the requested tailnet name and always returns the
// same client. Used to inject a scripted tsclient into the reconciler.
type fakeClientProvider struct {
	client tsclient.Client
	err    error
}

func (p *fakeClientProvider) For(_ string) (tsclient.Client, error) { return p.client, p.err }

// fakeTSClient is a minimal tsclient.Client. Only Keys().CreateAuthKey is expected to be called by these tests;
// everything else panics. The Keys resource records every CreateAuthKey call so tests can assert what tags were
// used and how many keys were minted, and returns a canned key value per call.
type fakeTSClient struct {
	tsclient.Client // embed for methods we don't implement — calling any of them panics

	mu       sync.Mutex
	keyCalls []tailscaleclient.CreateKeyRequest
	// nextKey is the sequence of keys to return from CreateAuthKey. When empty, "auth-key-N" (N = call index) is
	// used.
	nextKey []string
}

func (c *fakeTSClient) Keys() tsclient.KeyResource { return (*fakeKeys)(c) }

func (c *fakeTSClient) CreateAuthKeyCalls() []tailscaleclient.CreateKeyRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.keyCalls)
}

type fakeKeys fakeTSClient

func (k *fakeKeys) CreateAuthKey(_ context.Context, req tailscaleclient.CreateKeyRequest) (*tailscaleclient.Key, error) {
	c := (*fakeTSClient)(k)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyCalls = append(c.keyCalls, req)

	var key string
	if len(c.nextKey) > 0 {
		key, c.nextKey = c.nextKey[0], c.nextKey[1:]
	} else {
		key = fmt.Sprintf("auth-key-%d", len(c.keyCalls))
	}
	return &tailscaleclient.Key{Key: key}, nil
}

func (k *fakeKeys) List(_ context.Context, _ bool) ([]tailscaleclient.Key, error) { return nil, nil }

// TestReconciler_AuthKey_Lifecycle covers the three interesting cases:
//   - Fresh Secret ⇒ mint a new auth key with the right tags and embed it in the config.
//   - Existing Secret already has an auth key ⇒ reuse it, don't mint.
//   - PeerRelay declares its own tags ⇒ Tailscale API is called with those tags.
func TestReconciler_AuthKey_Lifecycle(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("mints-key-on-first-reconcile", func(t *testing.T) {
		pr := &tsapi.PeerRelay{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		fc := fake.NewClientBuilder().
			WithScheme(tsapi.GlobalScheme).
			WithStatusSubresource(&tsapi.PeerRelay{}).
			WithObjects(pr).
			Build()

		tsc := &fakeTSClient{nextKey: []string{"tskey-abc"}}
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:k8s-peer-relay"},
			Clients:            &fakeClientProvider{client: tsc},
			Logger:             logger.Sugar(),
		})

		if _, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}

		calls := tsc.CreateAuthKeyCalls()
		if len(calls) != 1 {
			t.Fatalf("expected 1 CreateAuthKey call, got %d", len(calls))
		}
		gotTags := calls[0].Capabilities.Devices.Create.Tags
		if !slices.Equal(gotTags, []string{"tag:k8s-peer-relay"}) {
			t.Errorf("expected default tags, got %v", gotTags)
		}

		conf := readTailscaledConfig(t, fc, "test-0-config")
		if conf.AuthKey == nil || *conf.AuthKey != "tskey-abc" {
			t.Errorf("expected AuthKey=tskey-abc in config, got %v", conf.AuthKey)
		}
	})

	t.Run("reuses-existing-key-across-reconciles", func(t *testing.T) {
		pr := &tsapi.PeerRelay{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		fc := fake.NewClientBuilder().
			WithScheme(tsapi.GlobalScheme).
			WithStatusSubresource(&tsapi.PeerRelay{}).
			WithObjects(pr).
			Build()

		tsc := &fakeTSClient{nextKey: []string{"tskey-first", "tskey-second"}}
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:k8s-peer-relay"},
			Clients:            &fakeClientProvider{client: tsc},
			Logger:             logger.Sugar(),
		})

		if _, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}

		if got := len(tsc.CreateAuthKeyCalls()); got != 1 {
			t.Errorf("expected 1 CreateAuthKey call across two reconciles, got %d", got)
		}
		conf := readTailscaledConfig(t, fc, "test-0-config")
		if conf.AuthKey == nil || *conf.AuthKey != "tskey-first" {
			t.Errorf("expected AuthKey preserved as tskey-first, got %v", conf.AuthKey)
		}
	})

	t.Run("uses-peer-relay-specific-tags", func(t *testing.T) {
		pr := &tsapi.PeerRelay{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec:       tsapi.PeerRelaySpec{Tags: tsapi.Tags{"tag:custom"}},
		}
		fc := fake.NewClientBuilder().
			WithScheme(tsapi.GlobalScheme).
			WithStatusSubresource(&tsapi.PeerRelay{}).
			WithObjects(pr).
			Build()

		tsc := &fakeTSClient{}
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:k8s-peer-relay"},
			Clients:            &fakeClientProvider{client: tsc},
			Logger:             logger.Sugar(),
		})

		if _, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}

		calls := tsc.CreateAuthKeyCalls()
		if len(calls) != 1 {
			t.Fatalf("expected 1 CreateAuthKey call, got %d", len(calls))
		}
		gotTags := calls[0].Capabilities.Devices.Create.Tags
		if !slices.Equal(gotTags, []string{"tag:custom"}) {
			t.Errorf("expected pr-specific tags, got %v", gotTags)
		}
	})
}
