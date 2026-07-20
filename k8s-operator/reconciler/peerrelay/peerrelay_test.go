// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package peerrelay_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

func testResolver(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	r := map[string][]netip.Addr{
		"test-0.elb.amazonaws.com": {netip.MustParseAddr("203.0.113.10")},
		"test-1.elb.amazonaws.com": {netip.MustParseAddr("203.0.113.11")},
	}

	if addrs, ok := r[host]; ok {
		return addrs, nil
	}

	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

type expectedService struct {
	Name              string
	Type              corev1.ServiceType
	Port              int32
	NodePort          int32
	Protocol          corev1.Protocol
	Selector          map[string]string
	Labels            map[string]string
	Annotations       map[string]string
	AbsentLabels      []string
	AbsentAnnotations []string
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
					Name:     "peerrelay-test-0",
					Type:     corev1.ServiceTypeLoadBalancer,
					Port:     41641,
					Protocol: corev1.ProtocolUDP,
					Selector: map[string]string{"statefulset.kubernetes.io/pod-name": "peerrelay-test-0"},
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
		},
		{
			Name:    "multiple-replicas",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(3))},
			},
			ExpectedServices: []expectedService{
				{Name: "peerrelay-test-0", Labels: map[string]string{"tailscale.com/peer-relay-replica": "0"}},
				{Name: "peerrelay-test-1", Labels: map[string]string{"tailscale.com/peer-relay-replica": "1"}},
				{Name: "peerrelay-test-2", Labels: map[string]string{"tailscale.com/peer-relay-replica": "2"}},
			},
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 3, Image: testProxyImage},
		},
		{
			Name:    "zero-replicas",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(0))},
			},
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 0, Image: testProxyImage},
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
				{Name: "peerrelay-test-0"},
				{Name: "peerrelay-test-1"},
			},
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 2, Image: testProxyImage},
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
				{Name: "peerrelay-test-0"},
				{Name: "peerrelay-test-1"},
				{Name: "peerrelay-test-2"},
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
				{Name: "peerrelay-other-5"},
				{Name: "peerrelay-test-0"},
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
					Name: "peerrelay-test-0",
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
					Name: "peerrelay-test-0",
					Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-scheme":     "internet-facing",
						"service.beta.kubernetes.io/azure-load-balancer-internal": "false",
					},
				},
			},
		},
		{
			// The reconciler applies via server-side apply, so a drifted Service (wrong Spec.Type, wrong Ports)
			// is restored on reconcile. Kubernetes owns the merge with fields belonging to other managers
			// (cloud LB controller annotations, kube-proxy's NodePort) and preserves them — that contract is
			// exercised in e2e tests where a real API server is available; here we only verify the drift is fixed.
			Name:    "drift-corrected",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(1))},
			},
			ExistingResources: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peerrelay-test-0",
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
					Name:     "peerrelay-test-0",
					Type:     corev1.ServiceTypeLoadBalancer,
					Port:     41641,
					Protocol: corev1.ProtocolUDP,
					Labels: map[string]string{
						"tailscale.com/managed": "true",
					},
					Annotations: map[string]string{
						"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing", // drift corrected
					},
				},
			},
			// No LB ingress seeded, so the PeerRelayReady condition stays Pending.
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
			ExpectedServices: []expectedService{{Name: "peerrelay-test-0"}, {Name: "peerrelay-test-1"}},
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
			ExpectedServices: []expectedService{{Name: "peerrelay-test-0"}, {Name: "peerrelay-test-1"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
				{Replica: 1, Address: "5.6.7.8", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonPodsPending,
		},
		{
			// Hostname-only LBs (AWS NLBs) no longer produce a hard error, the reconciler resolves the hostname
			// to a stable IP and advertises that instead. Here the resolver returns a canned address for the AWS
			// hostname; the endpoint should reflect the resolved IP. The eip-allocations annotation is what
			// signals to the reconciler that hostname resolution is safe — this is our AWS opt-in contract.
			Name:    "hostname-only-lb-is-resolved-to-ip",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Service: &tsapi.PeerRelayService{
						Annotations: map[string]string{eipAllocationsAnnotation: "eipalloc-aaaa"},
					},
				},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "", "test-0.elb.amazonaws.com"),
				managedStatefulSet("test", 1, 1),
			},
			ExpectedServices: []expectedService{{Name: "peerrelay-test-0"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "203.0.113.10", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionTrue,
			ExpectedReadyReason: peerrelay.ReasonReady,
		},
		{
			// Unresolvable hostname (e.g. NXDOMAIN during LB provisioning) stays in Pending — no hard error,
			// reconciler will retry when the hostname comes online. Service still carries the eip-allocations
			// annotation so we know the resolution path was attempted (and not just skipped for being non-AWS).
			Name:    "unresolvable-hostname-stays-pending",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Service: &tsapi.PeerRelayService{
						Annotations: map[string]string{eipAllocationsAnnotation: "eipalloc-aaaa"},
					},
				},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "", "unresolvable.example.invalid"),
			},
			ExpectedServices:    []expectedService{{Name: "peerrelay-test-0"}},
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonEndpointsPending,
		},
		{
			// A hostname-only Service without the EIP annotation is a Service whose backing LB has unstable IPs
			// (unmanaged AWS NLB, most third-party providers). The reconciler refuses to resolve — advertising a
			// transient IP would leave peers connecting to a dead endpoint if AWS shifts the underlying A records.
			// Users get an explicit "pending" state and either add the annotation or accept the LB isn't usable.
			Name:    "hostname-without-eip-annotation-stays-pending",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "", "test-0.elb.amazonaws.com"),
			},
			ExpectedServices:    []expectedService{{Name: "peerrelay-test-0"}},
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonEndpointsPending,
		},
		{
			// Mixed batch: one replica has a direct IP, another has only a hostname that resolves (with EIP
			// annotation propagated from the PeerRelay spec). Both should end up in status.endpoints.
			Name:    "mixed-ip-and-resolved-hostname",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Replicas: new(int32(2)),
					Service: &tsapi.PeerRelayService{
						Annotations: map[string]string{eipAllocationsAnnotation: "eipalloc-bbbb"},
					},
				},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "1.2.3.4", ""),
				managedServiceWithLB("test", 1, "", "test-1.elb.amazonaws.com"),
				managedStatefulSet("test", 2, 2),
			},
			ExpectedServices: []expectedService{{Name: "peerrelay-test-0"}, {Name: "peerrelay-test-1"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
				{Replica: 1, Address: "203.0.113.11", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionTrue,
			ExpectedReadyReason: peerrelay.ReasonReady,
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
			ExpectedServices: []expectedService{{Name: "peerrelay-test-0"}, {Name: "peerrelay-test-1"}, {Name: "peerrelay-test-2"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "1.2.3.4", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonEndpointsPending,
		},
		{
			// spec.aws.elasticIPs fans out per-replica: each Service gets its OWN eip-allocations + subnets
			// annotations from the array. This is the HA path on AWS where every replica needs a distinct EIP.
			Name:    "aws-elasticips-fan-out-per-replica",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Replicas: new(int32(2)),
					AWS: &tsapi.PeerRelayAWS{
						ElasticIPs: []tsapi.PeerRelayAWSElasticIP{
							{AllocationID: "eipalloc-aaaa", SubnetID: "subnet-aaaa"},
							{AllocationID: "eipalloc-bbbb", SubnetID: "subnet-bbbb"},
						},
					},
				},
			},
			ExpectedServices: []expectedService{
				{
					Name: "peerrelay-test-0",
					Annotations: map[string]string{
						eipAllocationsAnnotation: "eipalloc-aaaa",
						subnetsAnnotation:        "subnet-aaaa",
					},
				},
				{
					Name: "peerrelay-test-1",
					Annotations: map[string]string{
						eipAllocationsAnnotation: "eipalloc-bbbb",
						subnetsAnnotation:        "subnet-bbbb",
					},
				},
			},
			ExpectStatefulSetSpec: &statefulSetSpec{Replicas: 2, Image: testProxyImage},
		},
		{
			// spec.aws.elasticIPs wins over any conflicting eip-allocations / subnets in spec.service.annotations.
			// Users get a single source of truth: whatever they put in per-replica config is what lands on the Service.
			Name:    "aws-elasticips-override-shared-annotations",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Service: &tsapi.PeerRelayService{
						Annotations: map[string]string{
							eipAllocationsAnnotation: "eipalloc-shared-wrong",
							subnetsAnnotation:        "subnet-shared-wrong",
						},
					},
					AWS: &tsapi.PeerRelayAWS{
						ElasticIPs: []tsapi.PeerRelayAWSElasticIP{
							{AllocationID: "eipalloc-perreplica", SubnetID: "subnet-perreplica"},
						},
					},
				},
			},
			ExpectedServices: []expectedService{
				{
					Name: "peerrelay-test-0",
					Annotations: map[string]string{
						eipAllocationsAnnotation: "eipalloc-perreplica",
						subnetsAnnotation:        "subnet-perreplica",
					},
				},
			},
		},
		{
			Name:    "aws-elasticips-clears-eip-annotations",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			ExistingResources: []client.Object{
				&corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "peerrelay-test-0",
						Namespace: tailscaleNamespace,
						Labels: map[string]string{
							"tailscale.com/managed":              "true",
							"tailscale.com/parent-resource-type": "peerrelay",
							"tailscale.com/parent-resource":      "test",
							"tailscale.com/peer-relay-replica":   "0",
						},
						Annotations: map[string]string{
							eipAllocationsAnnotation: "eipalloc-stale",
							subnetsAnnotation:        "subnet-stale",
						},
					},
					Spec: corev1.ServiceSpec{
						Type: corev1.ServiceTypeLoadBalancer,
					},
				},
			},
			ExpectedServices: []expectedService{
				{
					Name:              "peerrelay-test-0",
					AbsentAnnotations: []string{eipAllocationsAnnotation, subnetsAnnotation},
				},
			},
		},
		{
			// Length mismatch trips the belt-and-braces check: reconciler refuses to create Services and surfaces
			// AWSConfigInvalid so the user can fix the spec. Nothing is created, existing state is preserved.
			Name:    "aws-elasticips-insufficient",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Replicas: new(int32(2)),
					AWS: &tsapi.PeerRelayAWS{
						ElasticIPs: []tsapi.PeerRelayAWSElasticIP{
							{AllocationID: "eipalloc-aaaa", SubnetID: "subnet-aaaa"},
						},
					},
				},
			},
			ExpectStatefulSetGone: true,
			ExpectedReadyStatus:   metav1.ConditionFalse,
			ExpectedReadyReason:   peerrelay.ReasonAWSConfigInvalid,
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
			ExpectedServices:      []expectedService{{Name: "peerrelay-other-0"}},
			ExpectPRDeleted:       true,
			ExpectStatefulSetGone: true,
		},
	}

	for _, tc := range tt {
		t.Run(tc.Name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
				WithScheme(tsapi.GlobalScheme).
				WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
				WithInterceptorFuncs(applyPatchInterceptor())
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
				Resolver:           testResolver,
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
			configSecrets, stateSecrets := childSecretsFromServices(tc.Request.Name, tc.ExpectedServices)
			assertConfigSecrets(t, fc, tc.Request.Name, configSecrets)
			assertStateSecrets(t, fc, tc.Request.Name, stateSecrets)
		})
	}
}

func assertStatefulSet(t *testing.T, fc client.Client, prName string, want *statefulSetSpec, gone bool) {
	t.Helper()

	stsName := "peerrelay-" + prName
	var ss appsv1.StatefulSet
	err := fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: stsName}, &ss)
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
	assertSecretsForType(t, fc, prName, "config", "config Secrets", want)
}

func assertStateSecrets(t *testing.T, fc client.Client, prName string, want []string) {
	t.Helper()
	assertSecretsForType(t, fc, prName, "state", "state Secrets", want)
}

// childSecretsFromServices derives the expected config and state Secret names for the PeerRelay named prName from the
// list of expected Services. Because the reconciler creates one config Secret (named <svc>-config) and one state
// Secret (named <svc>) per Service, spelling those out separately in every test case is redundant.
func childSecretsFromServices(prName string, services []expectedService) (configs, states []string) {
	prefix := "peerrelay-" + prName + "-"
	for _, s := range services {
		if !strings.HasPrefix(s.Name, prefix) {
			continue
		}
		configs = append(configs, s.Name+"-config")
		states = append(states, s.Name)
	}
	return configs, states
}

func assertSecretsForType(t *testing.T, fc client.Client, prName, secretType, label string, want []string) {
	t.Helper()

	var list corev1.SecretList
	if err := fc.List(t.Context(), &list, client.InNamespace(tailscaleNamespace), client.MatchingLabels(map[string]string{
		"tailscale.com/parent-resource-type": "peerrelay",
		"tailscale.com/parent-resource":      prName,
		"tailscale.com/secret-type":          secretType,
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
		t.Errorf("expected %s %v, got %v", label, sortedWant, got)
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

	for _, k := range want.AbsentLabels {
		if v, ok := got.Labels[k]; ok {
			t.Errorf("Service %q: expected label %q to be absent, got %q", want.Name, k, v)
		}
	}

	for k, v := range want.Annotations {
		if gotV := got.Annotations[k]; gotV != v {
			t.Errorf("Service %q: expected annotation %q=%q, got %q", want.Name, k, v, gotV)
		}
	}

	for _, k := range want.AbsentAnnotations {
		if v, ok := got.Annotations[k]; ok {
			t.Errorf("Service %q: expected annotation %q to be absent, got %q", want.Name, k, v)
		}
	}
}

func managedService(prName string, idx int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("peerrelay-%s-%d", prName, idx),
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

const (
	eipAllocationsAnnotation = "service.beta.kubernetes.io/aws-load-balancer-eip-allocations"
	subnetsAnnotation        = "service.beta.kubernetes.io/aws-load-balancer-subnets"
)

func managedStatefulSet(prName string, replicas, ready int32) *appsv1.StatefulSet {
	labels := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource-type": "peerrelay",
		"tailscale.com/parent-resource":      prName,
	}
	stsName := "peerrelay-" + prName
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: tailscaleNamespace,
			Labels:    labels,
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			ServiceName: stsName,
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
			Name:      fmt.Sprintf("peerrelay-%s-%d-config", prName, idx),
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

	fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
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
		Resolver:           testResolver,
		Logger:             logger.Sugar(),
	})

	if _, err := r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
		t.Fatal(err)
	}

	got0 := readTailscaledConfig(t, fc, "peerrelay-test-0-config")
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

	got1 := readTailscaledConfig(t, fc, "peerrelay-test-1-config")
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

func applyPatchInterceptor() interceptor.Funcs {
	return interceptor.Funcs{
		Patch: func(ctx context.Context, cl client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
			if patch.Type() != types.ApplyPatchType {
				return cl.Patch(ctx, obj, patch, opts...)
			}

			key := client.ObjectKeyFromObject(obj)
			existing := obj.DeepCopyObject().(client.Object)
			if err := cl.Get(ctx, key, existing); err != nil {
				if !apierrors.IsNotFound(err) {
					return err
				}

				return cl.Create(ctx, obj)
			}

			obj.SetResourceVersion(existing.GetResourceVersion())
			return cl.Update(ctx, obj)
		},
	}
}

type fakeClientProvider struct {
	client tsclient.Client
	err    error
}

func (p *fakeClientProvider) For(_ string) (tsclient.Client, error) { return p.client, p.err }

type fakeTSClient struct {
	tsclient.Client

	mu            sync.Mutex
	keyCalls      []tailscaleclient.CreateKeyRequest
	deviceDeletes []string
	nextKey       []string
}

func (c *fakeTSClient) Keys() tsclient.KeyResource       { return (*fakeKeys)(c) }
func (c *fakeTSClient) Devices() tsclient.DeviceResource { return (*fakeDevices)(c) }

func (c *fakeTSClient) CreateAuthKeyCalls() []tailscaleclient.CreateKeyRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.keyCalls)
}

func (c *fakeTSClient) DeviceDeletes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.deviceDeletes)
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

type fakeDevices fakeTSClient

func (d *fakeDevices) Delete(_ context.Context, id string) error {
	c := (*fakeTSClient)(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deviceDeletes = append(c.deviceDeletes, id)
	return nil
}

func (d *fakeDevices) List(_ context.Context, _ ...tailscaleclient.ListDevicesOptions) ([]tailscaleclient.Device, error) {
	return nil, nil
}

func (d *fakeDevices) Get(_ context.Context, _ string) (*tailscaleclient.Device, error) {
	return nil, nil
}

func TestReconciler_AuthKey_Lifecycle(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("mints-key-on-first-reconcile", func(t *testing.T) {
		pr := &tsapi.PeerRelay{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
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
			Resolver:           testResolver,
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

		conf := readTailscaledConfig(t, fc, "peerrelay-test-0-config")
		if conf.AuthKey == nil || *conf.AuthKey != "tskey-abc" {
			t.Errorf("expected AuthKey=tskey-abc in config, got %v", conf.AuthKey)
		}
	})

	t.Run("reuses-existing-key-across-reconciles", func(t *testing.T) {
		pr := &tsapi.PeerRelay{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
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
			Resolver:           testResolver,
			Logger:             logger.Sugar(),
		})

		if _, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}
		if _, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}

		if got := len(tsc.CreateAuthKeyCalls()); got != 1 {
			t.Errorf("expected 1 CreateAuthKey call across two reconciles, got %d", got)
		}

		conf := readTailscaledConfig(t, fc, "peerrelay-test-0-config")
		if conf.AuthKey == nil || *conf.AuthKey != "tskey-first" {
			t.Errorf("expected AuthKey preserved as tskey-first, got %v", conf.AuthKey)
		}
	})

	t.Run("uses-peer-relay-specific-tags", func(t *testing.T) {
		pr := &tsapi.PeerRelay{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec:       tsapi.PeerRelaySpec{Tags: tsapi.Tags{"tag:custom"}},
		}

		fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
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
			Resolver:           testResolver,
			Logger:             logger.Sugar(),
		})

		if _, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
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

func TestReconciler_DeletesTailnetDevices(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	// stateSecret seeds a Secret shaped like the ones the reconciler pre-creates: parent-resource labels + the
	// tailscale.com/secret-type=state marker, containing (optionally) a device_id entry as if tailscaled had
	// written it.
	stateSecret := func(prName, name string, idx int32, deviceID string) *corev1.Secret {
		labels := map[string]string{
			"tailscale.com/managed":              "true",
			"tailscale.com/parent-resource-type": "peerrelay",
			"tailscale.com/parent-resource":      prName,
			"tailscale.com/peer-relay-replica":   fmt.Sprintf("%d", idx),
			"tailscale.com/secret-type":          "state",
		}
		s := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: tailscaleNamespace, Labels: labels},
		}
		if deviceID != "" {
			s.Data = map[string][]byte{"device_id": []byte(deviceID)}
		}
		return s
	}

	t.Run("full-delete-removes-all-devices-and-state-secrets", func(t *testing.T) {
		pr := &tsapi.PeerRelay{
			ObjectMeta: metav1.ObjectMeta{
				Name:              "test",
				Finalizers:        []string{"tailscale.com/finalizer"},
				DeletionTimestamp: new(metav1.Now()),
			},
			Spec: tsapi.PeerRelaySpec{Replicas: new(int32(2))},
		}

		fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
			WithScheme(tsapi.GlobalScheme).
			WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
			WithObjects(
				pr,
				stateSecret("test", "peerrelay-test-0", 0, "device-aaa"),
				stateSecret("test", "peerrelay-test-1", 1, ""), // pod never registered , no device_id
				stateSecret("other", "peerrelay-other-0", 0, "device-should-not-touch"),
			).
			Build()

		tsc := &fakeTSClient{}
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:test-peer-relay"},
			Clients:            &fakeClientProvider{client: tsc},
			Resolver:           testResolver,
			Logger:             logger.Sugar(),
		})

		if _, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}

		if got, want := tsc.DeviceDeletes(), []string{"device-aaa"}; !slices.Equal(got, want) {
			t.Errorf("expected Devices().Delete calls %v, got %v", want, got)
		}

		// Our state Secrets should be gone; the unrelated PeerRelay's state Secret should still be present.
		for _, name := range []string{"peerrelay-test-0", "peerrelay-test-1"} {
			var s corev1.Secret
			if err = fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: name}, &s); !apierrors.IsNotFound(err) {
				t.Errorf("expected state Secret %q gone, got err=%v", name, err)
			}
		}
		var other corev1.Secret
		if err = fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: "peerrelay-other-0"}, &other); err != nil {
			t.Errorf("unexpected: state Secret for other PeerRelay was removed: %v", err)
		}
	})

	t.Run("scale-down-removes-devices-for-removed-replicas-only", func(t *testing.T) {
		pr := &tsapi.PeerRelay{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(1))},
		}

		fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
			WithScheme(tsapi.GlobalScheme).
			WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
			WithObjects(
				pr,
				stateSecret("test", "peerrelay-test-0", 0, "device-still-here"),
				stateSecret("test", "peerrelay-test-1", 1, "device-scaled-away-1"),
				stateSecret("test", "peerrelay-test-2", 2, "device-scaled-away-2"),
			).
			Build()

		tsc := &fakeTSClient{}
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:test-peer-relay"},
			Clients:            &fakeClientProvider{client: tsc},
			Resolver:           testResolver,
			Logger:             logger.Sugar(),
		})

		if _, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
			t.Fatal(err)
		}

		got := tsc.DeviceDeletes()
		slices.Sort(got)
		want := []string{"device-scaled-away-1", "device-scaled-away-2"}
		if !slices.Equal(got, want) {
			t.Errorf("expected Devices().Delete calls %v, got %v", want, got)
		}

		var kept corev1.Secret
		if err = fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: "peerrelay-test-0"}, &kept); err != nil {
			t.Errorf("expected replica 0 state Secret preserved: %v", err)
		}

		for _, name := range []string{"peerrelay-test-1", "peerrelay-test-2"} {
			var s corev1.Secret
			if err = fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: name}, &s); !apierrors.IsNotFound(err) {
				t.Errorf("expected state Secret %q gone after scale-down, got err=%v", name, err)
			}
		}
	})
}

func TestReconciler_TailnetUnavailable(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       tsapi.PeerRelaySpec{Tailnet: "missing"},
	}

	fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.PeerRelay{}).
		WithObjects(pr).
		Build()

	r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: tailscaleNamespace,
		ProxyImage:         testProxyImage,
		DefaultTags:        []string{"tag:test-peer-relay"},
		Clients:            &fakeClientProvider{err: errors.New("tailnet missing: not ready")},
		Resolver:           testResolver,
		Logger:             logger.Sugar(),
	})

	if _, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err == nil {
		t.Fatal("expected reconcile to return the tailnet resolver error, got nil")
	}

	var got tsapi.PeerRelay
	if err = fc.Get(t.Context(), types.NamespacedName{Name: "test"}, &got); err != nil {
		t.Fatal(err)
	}

	cond := readyCondition(&got)
	if cond.Status != metav1.ConditionFalse {
		t.Errorf("expected PeerRelayReady=False, got %q", cond.Status)
	}
	if cond.Reason != peerrelay.ReasonTailnetUnavailable {
		t.Errorf("expected reason=%s, got %q", peerrelay.ReasonTailnetUnavailable, cond.Reason)
	}
	if !strings.Contains(cond.Message, "not ready") {
		t.Errorf("expected condition message to include resolver error, got %q", cond.Message)
	}

	var svcs corev1.ServiceList
	if err = fc.List(t.Context(), &svcs, client.InNamespace(tailscaleNamespace)); err != nil {
		t.Fatal(err)
	}
	if len(svcs.Items) != 0 {
		t.Errorf("expected no Services created while tailnet is unavailable, got %d", len(svcs.Items))
	}
}

func TestReconciler_AppliesProxyClass(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	pr := &tsapi.PeerRelay{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       tsapi.PeerRelaySpec{ProxyClass: "custom"},
	}

	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "custom"},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Labels: tsapi.Labels{
					"team":                          "networking",
					"tailscale.com/parent-resource": "hijack-attempt", // must NOT overwrite reconciler-managed value
				},
				Annotations: map[string]string{"observability.example.com/scrape": "true"},
				Pod: &tsapi.Pod{
					NodeSelector: map[string]string{"pool": "peer-relays"},
					TailscaleContainer: &tsapi.Container{
						Resources: corev1.ResourceRequirements{
							Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
							Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
						},
						Env: []tsapi.Env{{Name: "TS_DEBUG_FIREWALL_MODE", Value: "auto"}},
					},
				},
			},
		},
	}

	fc := fake.NewClientBuilder().WithInterceptorFuncs(applyPatchInterceptor()).
		WithScheme(tsapi.GlobalScheme).
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

	if _, err = r.Reconcile(t.Context(), reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}}); err != nil {
		t.Fatal(err)
	}

	var ss appsv1.StatefulSet
	if err = fc.Get(t.Context(), types.NamespacedName{Namespace: tailscaleNamespace, Name: "peerrelay-test"}, &ss); err != nil {
		t.Fatal(err)
	}

	if got := ss.Labels["team"]; got != "networking" {
		t.Errorf("expected StatefulSet label team=networking, got %q", got)
	}

	if got := ss.Labels["tailscale.com/parent-resource"]; got != "test" {
		t.Errorf("expected reconciler-managed parent-resource label preserved as %q, got %q", "test", got)
	}

	if got := ss.Annotations["observability.example.com/scrape"]; got != "true" {
		t.Errorf("expected StatefulSet annotation scrape=true, got %q", got)
	}

	if got := ss.Spec.Template.Spec.NodeSelector["pool"]; got != "peer-relays" {
		t.Errorf("expected Pod nodeSelector pool=peer-relays, got %q", got)
	}

	if len(ss.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(ss.Spec.Template.Spec.Containers))
	}

	c := ss.Spec.Template.Spec.Containers[0]
	if got, want := c.Resources.Requests[corev1.ResourceCPU], resource.MustParse("100m"); !got.Equal(want) {
		t.Errorf("expected container CPU request %s, got %s", want.String(), got.String())
	}

	if got, want := c.Resources.Limits[corev1.ResourceMemory], resource.MustParse("256Mi"); !got.Equal(want) {
		t.Errorf("expected container memory limit %s, got %s", want.String(), got.String())
	}

	var foundEnv bool
	for _, e := range c.Env {
		if e.Name == "TS_DEBUG_FIREWALL_MODE" && e.Value == "auto" {
			foundEnv = true
			break
		}
	}

	if !foundEnv {
		t.Errorf("expected TS_DEBUG_FIREWALL_MODE=auto env, container env is %+v", c.Env)
	}
}
