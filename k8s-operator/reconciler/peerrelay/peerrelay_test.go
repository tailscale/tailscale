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
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"tailscale.com/ipn"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/reconciler/peerrelay"
	"tailscale.com/k8s-operator/reconciler/reconcilertest"
)

const (
	tailscaleNamespace = "tailscale"
	testProxyImage     = "tailscale/tailscale:test"
)

func testResolver(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	r := map[string][]netip.Addr{
		"test-0.elb.amazonaws.com": {netip.MustParseAddr("203.0.113.10")},
		"test-1.elb.amazonaws.com": {netip.MustParseAddr("203.0.113.11")},
		// A load balancer spread over several availability zones, returned out of order so the reconciler's
		// sorting is exercised.
		"multi-az.elb.amazonaws.com": {
			netip.MustParseAddr("203.0.113.30"),
			netip.MustParseAddr("203.0.113.20"),
		},
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
						// A peer relay listens only on UDP, so the load balancer must health check the pod's
						// /healthz endpoint instead of the port it forwards, which would never answer.
						"service.beta.kubernetes.io/aws-load-balancer-healthcheck-protocol": "http",
						"service.beta.kubernetes.io/aws-load-balancer-healthcheck-port":     "9002",
						"service.beta.kubernetes.io/aws-load-balancer-healthcheck-path":     "/healthz",
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
			// Without spec.aws the reconciler pins no subnet, so the AWS Load Balancer Controller spreads the NLB
			// over every zone it discovers and cross-zone is defaulted on to make all of those addresses reach the
			// pod. The hostname is still resolved and advertised: an NLB's addresses are fixed for its lifetime
			// whether or not an Elastic IP was supplied, so there is nothing to be gained by withholding the
			// endpoint. Replaces an older rule that only resolved when an EIP annotation was present, which left
			// this configuration permanently pending despite being perfectly reachable.
			Name:    "unpinned-nlb-resolves-and-enables-cross-zone",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "", "test-0.elb.amazonaws.com"),
				managedStatefulSet("test", 1, 1),
			},
			ExpectedServices: []expectedService{
				{
					Name: "peerrelay-test-0",
					Annotations: map[string]string{
						lbAttributesAnnotation: "load_balancing.cross_zone.enabled=true",
					},
					AbsentAnnotations: []string{eipAllocationsAnnotation, subnetsAnnotation},
				},
			},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "203.0.113.10", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionTrue,
			ExpectedReadyReason: peerrelay.ReasonReady,
		},
		{
			// Cross-zone is defaulted on even alongside a pinned EIP. It is inert in that case, since pinning a
			// subnet leaves only one zone enabled on the load balancer, but applying it unconditionally keeps the
			// annotation set uniform across every replica.
			Name:    "pinned-eip-still-gets-cross-zone",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					AWS: &tsapi.PeerRelayAWS{
						ElasticIPs: []tsapi.PeerRelayAWSElasticIP{
							{AllocationID: "eipalloc-aaaa", SubnetID: "subnet-aaaa"},
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
						lbAttributesAnnotation:   "load_balancing.cross_zone.enabled=true",
					},
				},
			},
		},
		{
			// A user-supplied attributes value must survive untouched, including turning cross-zone back off.
			Name:    "user-attributes-annotation-is-not-overridden",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec: tsapi.PeerRelaySpec{
					Service: &tsapi.PeerRelayService{
						Annotations: map[string]string{
							lbAttributesAnnotation: "load_balancing.cross_zone.enabled=false",
						},
					},
				},
			},
			ExpectedServices: []expectedService{
				{
					Name: "peerrelay-test-0",
					Annotations: map[string]string{
						lbAttributesAnnotation: "load_balancing.cross_zone.enabled=false",
					},
				},
			},
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
			// A load balancer spanning several availability zones answers on one address per zone, and every one
			// of them reaches the replica. All are advertised so a peer can still get through when a zone is
			// unreachable, and so the user is not paying for addresses nothing uses. status.endpoints is keyed on
			// replica and address together, so one replica can hold several entries.
			Name:    "multi-az-lb-advertises-every-address",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "", "multi-az.elb.amazonaws.com"),
				managedStatefulSet("test", 1, 1),
			},
			ExpectedServices: []expectedService{{Name: "peerrelay-test-0"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "203.0.113.20", Port: 41641},
				{Replica: 0, Address: "203.0.113.30", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionTrue,
			ExpectedReadyReason: peerrelay.ReasonReady,
		},
		{
			// Replica 0's load balancer spans two zones and contributes two entries, while replica 1 has no
			// address yet. There are as many entries as replicas, but only one replica is reachable, so the
			// PeerRelay must not report ready. Counting entries rather than replicas would let the multi-homed
			// replica mask the one that peers cannot reach at all.
			Name:    "multi-az-endpoints-do-not-mask-a-replica-without-one",
			Request: reconcile.Request{NamespacedName: types.NamespacedName{Name: "test"}},
			PeerRelay: &tsapi.PeerRelay{
				ObjectMeta: metav1.ObjectMeta{Name: "test"},
				Spec:       tsapi.PeerRelaySpec{Replicas: new(int32(2))},
			},
			ExistingResources: []client.Object{
				managedServiceWithLB("test", 0, "", "multi-az.elb.amazonaws.com"),
				managedService("test", 1),
				managedStatefulSet("test", 2, 2),
			},
			ExpectedServices: []expectedService{{Name: "peerrelay-test-0"}, {Name: "peerrelay-test-1"}},
			ExpectedEndpoints: []tsapi.PeerRelayEndpoint{
				{Replica: 0, Address: "203.0.113.20", Port: 41641},
				{Replica: 0, Address: "203.0.113.30", Port: 41641},
			},
			ExpectedReadyStatus: metav1.ConditionFalse,
			ExpectedReadyReason: peerrelay.ReasonEndpointsPending,
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
			builder := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
				WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
				WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor())
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
				Clients:            reconcilertest.NewFakeClientProvider(reconcilertest.NewFakeClient()),
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
				cond := reconcilertest.Condition(t, pr.Status.Conditions, tsapi.PeerRelayReady)
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

	if len(ss.Spec.Template.Spec.Containers) == 0 {
		return
	}
	c := ss.Spec.Template.Spec.Containers[0]

	// The load balancer health checks /healthz rather than the UDP port it forwards, so containerboot has to be
	// serving it and the port has to be declared for the check to have anything to talk to.
	if !slices.ContainsFunc(c.Env, func(e corev1.EnvVar) bool {
		return e.Name == "TS_ENABLE_HEALTH_CHECK" && e.Value == "true"
	}) {
		t.Errorf("expected TS_ENABLE_HEALTH_CHECK=true on the tailscaled container, got env %v", c.Env)
	}

	if !slices.ContainsFunc(c.Ports, func(p corev1.ContainerPort) bool {
		return p.ContainerPort == 9002 && p.Protocol == corev1.ProtocolTCP
	}) {
		t.Errorf("expected container to declare TCP port 9002 for the health check, got ports %v", c.Ports)
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
	lbAttributesAnnotation   = "service.beta.kubernetes.io/aws-load-balancer-attributes"
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

	fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
		WithStatusSubresource(&tsapi.PeerRelay{}).
		WithObjects(
			pr,
			managedServiceWithLB("test", 0, "", "multi-az.elb.amazonaws.com"),
			managedService("test", 1),
		).
		Build()

	const testLoginURL = "https://control.example.test"
	r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: tailscaleNamespace,
		ProxyImage:         testProxyImage,
		DefaultTags:        []string{"tag:test-peer-relay"},
		Clients:            reconcilertest.NewFakeClientProvider(reconcilertest.NewFakeClient(reconcilertest.WithLoginURL(testLoginURL))),
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
	// The load balancer spans two availability zones, so both of its addresses must reach the config in sorted
	// order. This is what makes the extra addresses worth paying for, rather than provisioned and unused.
	wantEndpoints := []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.20:41641"),
		netip.MustParseAddrPort("203.0.113.30:41641"),
	}
	if !slices.Equal(got0.RelayServerStaticEndpoints, wantEndpoints) {
		t.Errorf("replica 0: expected RelayServerStaticEndpoints=%v, got %v", wantEndpoints, got0.RelayServerStaticEndpoints)
	}
	if got0.Hostname == nil || *got0.Hostname != "test-0" {
		t.Errorf("replica 0: expected hostname=test-0, got %v", got0.Hostname)
	}
	if got0.ServerURL == nil || *got0.ServerURL != testLoginURL {
		t.Errorf("replica 0: expected ServerURL=%q, got %v", testLoginURL, got0.ServerURL)
	}

	got1 := readTailscaledConfig(t, fc, "peerrelay-test-1-config")
	if got1.RelayServerPort == nil || *got1.RelayServerPort != 41641 {
		t.Errorf("replica 1: expected RelayServerPort=41641, got %v", got1.RelayServerPort)
	}
	// Replica 1's LB has not been provisioned yet, so no static endpoints.
	if len(got1.RelayServerStaticEndpoints) != 0 {
		t.Errorf("replica 1: expected no RelayServerStaticEndpoints, got %v", got1.RelayServerStaticEndpoints)
	}
	if got1.ServerURL == nil || *got1.ServerURL != testLoginURL {
		t.Errorf("replica 1: expected ServerURL=%q, got %v", testLoginURL, got1.ServerURL)
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

func TestReconciler_AuthKey_Lifecycle(t *testing.T) {
	t.Parallel()

	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("mints-key-on-first-reconcile", func(t *testing.T) {
		pr := &tsapi.PeerRelay{ObjectMeta: metav1.ObjectMeta{Name: "test"}}
		fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
			WithStatusSubresource(&tsapi.PeerRelay{}).
			WithObjects(pr).
			Build()

		tsc := reconcilertest.NewFakeClient(reconcilertest.WithAuthKeys("tskey-abc"))
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:k8s-peer-relay"},
			Clients:            reconcilertest.NewFakeClientProvider(tsc),
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
		fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
			WithStatusSubresource(&tsapi.PeerRelay{}).
			WithObjects(pr).
			Build()

		tsc := reconcilertest.NewFakeClient(reconcilertest.WithAuthKeys("tskey-first", "tskey-second"))
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:k8s-peer-relay"},
			Clients:            reconcilertest.NewFakeClientProvider(tsc),
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

		fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
			WithStatusSubresource(&tsapi.PeerRelay{}).
			WithObjects(pr).
			Build()

		tsc := reconcilertest.NewFakeClient()

		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:k8s-peer-relay"},
			Clients:            reconcilertest.NewFakeClientProvider(tsc),
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

		fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
			WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
			WithObjects(
				pr,
				stateSecret("test", "peerrelay-test-0", 0, "device-aaa"),
				stateSecret("test", "peerrelay-test-1", 1, ""), // pod never registered , no device_id
				stateSecret("other", "peerrelay-other-0", 0, "device-should-not-touch"),
			).
			Build()

		tsc := reconcilertest.NewFakeClient()
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:test-peer-relay"},
			Clients:            reconcilertest.NewFakeClientProvider(tsc),
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

		fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
			WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
			WithObjects(
				pr,
				stateSecret("test", "peerrelay-test-0", 0, "device-still-here"),
				stateSecret("test", "peerrelay-test-1", 1, "device-scaled-away-1"),
				stateSecret("test", "peerrelay-test-2", 2, "device-scaled-away-2"),
			).
			Build()

		tsc := reconcilertest.NewFakeClient()
		r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
			Client:             fc,
			TailscaleNamespace: tailscaleNamespace,
			ProxyImage:         testProxyImage,
			DefaultTags:        []string{"tag:test-peer-relay"},
			Clients:            reconcilertest.NewFakeClientProvider(tsc),
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

	fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
		WithStatusSubresource(&tsapi.PeerRelay{}).
		WithObjects(pr).
		Build()

	r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: tailscaleNamespace,
		ProxyImage:         testProxyImage,
		DefaultTags:        []string{"tag:test-peer-relay"},
		Clients:            reconcilertest.NewFailingClientProvider(errors.New("tailnet missing: not ready")),
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

	reconcilertest.ExpectConditionStatus(t, got.Status.Conditions, tsapi.PeerRelayReady,
		metav1.ConditionFalse, peerrelay.ReasonTailnetUnavailable)

	cond := reconcilertest.Condition(t, got.Status.Conditions, tsapi.PeerRelayReady)
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

	fc := reconcilertest.NewClientBuilder().WithInterceptorFuncs(reconcilertest.ApplyPatchInterceptor()).
		WithStatusSubresource(&tsapi.PeerRelay{}, &appsv1.StatefulSet{}).
		WithObjects(pr, pc).
		Build()

	r := peerrelay.NewReconciler(peerrelay.ReconcilerOptions{
		Client:             fc,
		TailscaleNamespace: tailscaleNamespace,
		ProxyImage:         testProxyImage,
		DefaultTags:        []string{"tag:test-peer-relay"},
		Clients:            reconcilertest.NewFakeClientProvider(reconcilertest.NewFakeClient()),
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
