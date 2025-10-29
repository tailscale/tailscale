// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	kube "tailscale.com/k8s-operator"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/k8s-proxy/conf"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/opt"
	"tailscale.com/types/ptr"
)

const (
	testProxyImage = "tailscale/tailscale:test"
	initialCfgHash = "6632726be70cf224049580deb4d317bba065915b5fd415461d60ed621c91b196"
)

var (
	defaultProxyClassAnnotations = map[string]string{
		"some-annotation": "from-the-proxy-class",
	}

	defaultReplicas             = ptr.To(int32(2))
	defaultStaticEndpointConfig = &tsapi.StaticEndpointsConfig{
		NodePort: &tsapi.NodePortConfig{
			Ports: []tsapi.PortRange{
				{Port: 30001}, {Port: 30002},
			},
			Selector: map[string]string{
				"foo/bar": "baz",
			},
		},
	}
)

func TestProxyGroupWithStaticEndpoints(t *testing.T) {
	type testNodeAddr struct {
		ip       string
		addrType corev1.NodeAddressType
	}

	type testNode struct {
		name      string
		addresses []testNodeAddr
		labels    map[string]string
	}

	type reconcile struct {
		staticEndpointConfig *tsapi.StaticEndpointsConfig
		replicas             *int32
		nodes                []testNode
		expectedIPs          []netip.Addr
		expectedEvents       []string
		expectedErr          string
		expectStatefulSet    bool
	}

	testCases := []struct {
		name        string
		description string
		reconciles  []reconcile
	}{
		{
			// the reconciler should manage to create static endpoints when Nodes have IPv6 addresses.
			name: "IPv6",
			reconciles: []reconcile{
				{
					staticEndpointConfig: &tsapi.StaticEndpointsConfig{
						NodePort: &tsapi.NodePortConfig{
							Ports: []tsapi.PortRange{
								{Port: 3001},
								{Port: 3005},
								{Port: 3007},
								{Port: 3009},
							},
							Selector: map[string]string{
								"foo/bar": "baz",
							},
						},
					},
					replicas: ptr.To(int32(4)),
					nodes: []testNode{
						{
							name:      "foobar",
							addresses: []testNodeAddr{{ip: "2001:0db8::1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbaz",
							addresses: []testNodeAddr{{ip: "2001:0db8::2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbazz",
							addresses: []testNodeAddr{{ip: "2001:0db8::3", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("2001:0db8::1"), netip.MustParseAddr("2001:0db8::2"), netip.MustParseAddr("2001:0db8::3")},
					expectedEvents:    []string{},
					expectedErr:       "",
					expectStatefulSet: true,
				},
			},
		},
		{
			// declaring specific ports (with no `endPort`s) in the `spec.staticEndpoints.nodePort` should work.
			name: "SpecificPorts",
			reconciles: []reconcile{
				{
					staticEndpointConfig: &tsapi.StaticEndpointsConfig{
						NodePort: &tsapi.NodePortConfig{
							Ports: []tsapi.PortRange{
								{Port: 3001},
								{Port: 3005},
								{Port: 3007},
								{Port: 3009},
							},
							Selector: map[string]string{
								"foo/bar": "baz",
							},
						},
					},
					replicas: ptr.To(int32(4)),
					nodes: []testNode{
						{
							name:      "foobar",
							addresses: []testNodeAddr{{ip: "192.168.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbaz",
							addresses: []testNodeAddr{{ip: "192.168.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbazz",
							addresses: []testNodeAddr{{ip: "192.168.0.3", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("192.168.0.1"), netip.MustParseAddr("192.168.0.2"), netip.MustParseAddr("192.168.0.3")},
					expectedEvents:    []string{},
					expectedErr:       "",
					expectStatefulSet: true,
				},
			},
		},
		{
			// if too narrow a range of `spec.staticEndpoints.nodePort.Ports` on the proxyClass should result in no StatefulSet being created.
			name: "NotEnoughPorts",
			reconciles: []reconcile{
				{
					staticEndpointConfig: &tsapi.StaticEndpointsConfig{
						NodePort: &tsapi.NodePortConfig{
							Ports: []tsapi.PortRange{
								{Port: 3001},
								{Port: 3005},
								{Port: 3007},
							},
							Selector: map[string]string{
								"foo/bar": "baz",
							},
						},
					},
					replicas: ptr.To(int32(4)),
					nodes: []testNode{
						{
							name:      "foobar",
							addresses: []testNodeAddr{{ip: "192.168.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbaz",
							addresses: []testNodeAddr{{ip: "192.168.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbazz",
							addresses: []testNodeAddr{{ip: "192.168.0.3", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{},
					expectedEvents:    []string{"Warning ProxyGroupCreationFailed error provisioning NodePort Services for static endpoints: failed to allocate NodePorts to ProxyGroup Services: not enough available ports to allocate all replicas (needed 4, got 3). Field 'spec.staticEndpoints.nodePort.ports' on ProxyClass \"default-pc\" must have bigger range allocated"},
					expectedErr:       "",
					expectStatefulSet: false,
				},
			},
		},
		{
			// when supplying a variety of ranges that are not clashing, the reconciler should manage to create a StatefulSet.
			name: "NonClashingRanges",
			reconciles: []reconcile{
				{
					staticEndpointConfig: &tsapi.StaticEndpointsConfig{
						NodePort: &tsapi.NodePortConfig{
							Ports: []tsapi.PortRange{
								{Port: 3000, EndPort: 3002},
								{Port: 3003, EndPort: 3005},
								{Port: 3006},
							},
							Selector: map[string]string{
								"foo/bar": "baz",
							},
						},
					},
					replicas: ptr.To(int32(3)),
					nodes: []testNode{
						{name: "node1", addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}}, labels: map[string]string{"foo/bar": "baz"}},
						{name: "node2", addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}}, labels: map[string]string{"foo/bar": "baz"}},
						{name: "node3", addresses: []testNodeAddr{{ip: "10.0.0.3", addrType: corev1.NodeExternalIP}}, labels: map[string]string{"foo/bar": "baz"}},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3")},
					expectedEvents:    []string{},
					expectedErr:       "",
					expectStatefulSet: true,
				},
			},
		},
		{
			// when there isn't a node that matches the selector, the ProxyGroup enters a failed state as there are no valid Static Endpoints.
			// while it does create an event on the resource, It does not return an error
			name: "NoMatchingNodes",
			reconciles: []reconcile{
				{
					staticEndpointConfig: &tsapi.StaticEndpointsConfig{
						NodePort: &tsapi.NodePortConfig{
							Ports: []tsapi.PortRange{
								{Port: 3000, EndPort: 3005},
							},
							Selector: map[string]string{
								"zone": "us-west",
							},
						},
					},
					replicas: defaultReplicas,
					nodes: []testNode{
						{name: "node1", addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}}, labels: map[string]string{"zone": "eu-central"}},
						{name: "node2", addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeInternalIP}}, labels: map[string]string{"zone": "eu-central"}},
					},
					expectedIPs:       []netip.Addr{},
					expectedEvents:    []string{"Warning ProxyGroupCreationFailed error provisioning config Secrets: could not find static endpoints for replica \"test-0\": failed to match nodes to configured Selectors on `spec.staticEndpoints.nodePort.selectors` field for ProxyClass \"default-pc\""},
					expectedErr:       "",
					expectStatefulSet: false,
				},
			},
		},
		{
			// when all the nodes have only have addresses of type InternalIP populated in their status, the ProxyGroup enters a failed state as there are no valid Static Endpoints.
			// while it does create an event on the resource, It does not return an error
			name: "AllInternalIPAddresses",
			reconciles: []reconcile{
				{
					staticEndpointConfig: &tsapi.StaticEndpointsConfig{
						NodePort: &tsapi.NodePortConfig{
							Ports: []tsapi.PortRange{
								{Port: 3001},
								{Port: 3005},
								{Port: 3007},
								{Port: 3009},
							},
							Selector: map[string]string{
								"foo/bar": "baz",
							},
						},
					},
					replicas: ptr.To(int32(4)),
					nodes: []testNode{
						{
							name:      "foobar",
							addresses: []testNodeAddr{{ip: "192.168.0.1", addrType: corev1.NodeInternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbaz",
							addresses: []testNodeAddr{{ip: "192.168.0.2", addrType: corev1.NodeInternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "foobarbazz",
							addresses: []testNodeAddr{{ip: "192.168.0.3", addrType: corev1.NodeInternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{},
					expectedEvents:    []string{"Warning ProxyGroupCreationFailed error provisioning config Secrets: could not find static endpoints for replica \"test-0\": failed to find any `status.addresses` of type \"ExternalIP\" on nodes using configured Selectors on `spec.staticEndpoints.nodePort.selectors` for ProxyClass \"default-pc\""},
					expectedErr:       "",
					expectStatefulSet: false,
				},
			},
		},
		{
			// When the node's (and some of their addresses) change between reconciles, the reconciler should first pick addresses that
			// have been used previously (provided that they are still populated on a node that matches the selector)
			name: "NodeIPChangesAndPersists",
			reconciles: []reconcile{
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node3",
							addresses: []testNodeAddr{{ip: "10.0.0.3", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
					expectStatefulSet: true,
				},
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.10", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node3",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectStatefulSet: true,
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
				},
			},
		},
		{
			// given a new node being created with a new IP, and a node previously used for Static Endpoints being removed, the Static Endpoints should be updated
			// correctly
			name: "NodeIPChangesWithNewNode",
			reconciles: []reconcile{
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
					expectStatefulSet: true,
				},
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node3",
							addresses: []testNodeAddr{{ip: "10.0.0.3", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.3")},
					expectStatefulSet: true,
				},
			},
		},
		{
			// when all the node IPs change, they should all update
			name: "AllNodeIPsChange",
			reconciles: []reconcile{
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
					expectStatefulSet: true,
				},
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.100", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.200", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.100"), netip.MustParseAddr("10.0.0.200")},
					expectStatefulSet: true,
				},
			},
		},
		{
			// if there are less ExternalIPs after changes to the nodes between reconciles, the reconciler should complete without issues
			name: "LessExternalIPsAfterChange",
			reconciles: []reconcile{
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
					expectStatefulSet: true,
				},
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeInternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1")},
					expectStatefulSet: true,
				},
			},
		},
		{
			// if node address parsing fails (given an invalid address), the reconciler should continue without failure and find other
			// valid addresses
			name: "NodeAddressParsingFails",
			reconciles: []reconcile{
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "invalid-ip", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.2")},
					expectStatefulSet: true,
				},
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "invalid-ip", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.2")},
					expectStatefulSet: true,
				},
			},
		},
		{
			// if the node's become unlabeled, the ProxyGroup should enter a ProxyGroupInvalid state, but the reconciler should not fail
			name: "NodesBecomeUnlabeled",
			reconciles: []reconcile{
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node1",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
						{
							name:      "node2",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{"foo/bar": "baz"},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
					expectStatefulSet: true,
				},
				{
					staticEndpointConfig: defaultStaticEndpointConfig,
					replicas:             defaultReplicas,
					nodes: []testNode{
						{
							name:      "node3",
							addresses: []testNodeAddr{{ip: "10.0.0.1", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{},
						},
						{
							name:      "node4",
							addresses: []testNodeAddr{{ip: "10.0.0.2", addrType: corev1.NodeExternalIP}},
							labels:    map[string]string{},
						},
					},
					expectedIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
					expectedEvents:    []string{"Warning ProxyGroupCreationFailed error provisioning config Secrets: could not find static endpoints for replica \"test-0\": failed to match nodes to configured Selectors on `spec.staticEndpoints.nodePort.selectors` field for ProxyClass \"default-pc\""},
					expectStatefulSet: true,
				},
			},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			tsClient := &fakeTSClient{}
			zl, _ := zap.NewDevelopment()
			fr := record.NewFakeRecorder(10)
			cl := tstest.NewClock(tstest.ClockOpts{})

			pc := &tsapi.ProxyClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "default-pc",
				},
				Spec: tsapi.ProxyClassSpec{
					StatefulSet: &tsapi.StatefulSet{
						Annotations: defaultProxyClassAnnotations,
					},
				},
				Status: tsapi.ProxyClassStatus{
					Conditions: []metav1.Condition{{
						Type:               string(tsapi.ProxyClassReady),
						Status:             metav1.ConditionTrue,
						Reason:             reasonProxyClassValid,
						Message:            reasonProxyClassValid,
						LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
					}},
				},
			}

			pg := &tsapi.ProxyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "test",
					Finalizers: []string{"tailscale.com/finalizer"},
				},
				Spec: tsapi.ProxyGroupSpec{
					Type:       tsapi.ProxyGroupTypeEgress,
					ProxyClass: pc.Name,
				},
			}

			fc := fake.NewClientBuilder().
				WithObjects(pc, pg).
				WithStatusSubresource(pc, pg).
				WithScheme(tsapi.GlobalScheme).
				Build()

			reconciler := &ProxyGroupReconciler{
				tsNamespace:       tsNamespace,
				tsProxyImage:      testProxyImage,
				defaultTags:       []string{"tag:test-tag"},
				tsFirewallMode:    "auto",
				defaultProxyClass: "default-pc",

				Client:   fc,
				tsClient: tsClient,
				recorder: fr,
				clock:    cl,
			}

			for i, r := range tt.reconciles {
				createdNodes := []corev1.Node{}
				t.Run(tt.name, func(t *testing.T) {
					for _, n := range r.nodes {
						no := &corev1.Node{
							ObjectMeta: metav1.ObjectMeta{
								Name:   n.name,
								Labels: n.labels,
							},
							Status: corev1.NodeStatus{
								Addresses: []corev1.NodeAddress{},
							},
						}
						for _, addr := range n.addresses {
							no.Status.Addresses = append(no.Status.Addresses, corev1.NodeAddress{
								Type:    addr.addrType,
								Address: addr.ip,
							})
						}
						if err := fc.Create(t.Context(), no); err != nil {
							t.Fatalf("failed to create node %q: %v", n.name, err)
						}
						createdNodes = append(createdNodes, *no)
						t.Logf("created node %q with data", n.name)
					}

					reconciler.log = zl.Sugar().With("TestName", tt.name).With("Reconcile", i)
					pg.Spec.Replicas = r.replicas
					pc.Spec.StaticEndpoints = r.staticEndpointConfig

					createOrUpdate(t.Context(), fc, "", pg, func(o *tsapi.ProxyGroup) {
						o.Spec.Replicas = pg.Spec.Replicas
					})

					createOrUpdate(t.Context(), fc, "", pc, func(o *tsapi.ProxyClass) {
						o.Spec.StaticEndpoints = pc.Spec.StaticEndpoints
					})

					if r.expectedErr != "" {
						expectError(t, reconciler, "", pg.Name)
					} else {
						expectReconciled(t, reconciler, "", pg.Name)
					}
					expectEvents(t, fr, r.expectedEvents)

					sts := &appsv1.StatefulSet{}
					err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts)
					if r.expectStatefulSet {
						if err != nil {
							t.Fatalf("failed to get StatefulSet: %v", err)
						}

						for j := range 2 {
							sec := &corev1.Secret{}
							if err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: fmt.Sprintf("%s-%d-config", pg.Name, j)}, sec); err != nil {
								t.Fatalf("failed to get state Secret for replica %d: %v", j, err)
							}

							config := &ipn.ConfigVAlpha{}
							foundConfig := false
							for _, d := range sec.Data {
								if err := json.Unmarshal(d, config); err == nil {
									foundConfig = true
									break
								}
							}
							if !foundConfig {
								t.Fatalf("could not unmarshal config from secret data for replica %d", j)
							}

							if len(config.StaticEndpoints) > staticEndpointsMaxAddrs {
								t.Fatalf("expected %d StaticEndpoints in config Secret, but got %d for replica %d. Found Static Endpoints: %v", staticEndpointsMaxAddrs, len(config.StaticEndpoints), j, config.StaticEndpoints)
							}

							for _, e := range config.StaticEndpoints {
								if !slices.Contains(r.expectedIPs, e.Addr()) {
									t.Fatalf("found unexpected static endpoint IP %q for replica %d. Expected one of %v", e.Addr().String(), j, r.expectedIPs)
								}
								if c := r.staticEndpointConfig; c != nil && c.NodePort.Ports != nil {
									var ports tsapi.PortRanges = c.NodePort.Ports
									found := false
									for port := range ports.All() {
										if port == e.Port() {
											found = true
											break
										}
									}

									if !found {
										t.Fatalf("found unexpected static endpoint port %d for replica %d. Expected one of %v .", e.Port(), j, ports.All())
									}
								} else {
									if e.Port() != 3001 && e.Port() != 3002 {
										t.Fatalf("found unexpected static endpoint port %d for replica %d. Expected 3001 or 3002.", e.Port(), j)
									}
								}
							}
						}

						pgroup := &tsapi.ProxyGroup{}
						err = fc.Get(t.Context(), client.ObjectKey{Name: pg.Name}, pgroup)
						if err != nil {
							t.Fatalf("failed to get ProxyGroup %q: %v", pg.Name, err)
						}

						t.Logf("getting proxygroup after reconcile")
						for _, d := range pgroup.Status.Devices {
							t.Logf("found device %q", d.Hostname)
							for _, e := range d.StaticEndpoints {
								t.Logf("found static endpoint %q", e)
							}
						}
					} else {
						if err == nil {
							t.Fatal("expected error when getting Statefulset")
						}
					}
				})

				// node cleanup between reconciles
				// we created a new set of nodes for each
				for _, n := range createdNodes {
					err := fc.Delete(t.Context(), &n)
					if err != nil && !apierrors.IsNotFound(err) {
						t.Fatalf("failed to delete node: %v", err)
					}
				}
			}

			t.Run("delete_and_cleanup", func(t *testing.T) {
				reconciler := &ProxyGroupReconciler{
					tsNamespace:       tsNamespace,
					tsProxyImage:      testProxyImage,
					defaultTags:       []string{"tag:test-tag"},
					tsFirewallMode:    "auto",
					defaultProxyClass: "default-pc",

					Client:   fc,
					tsClient: tsClient,
					recorder: fr,
					log:      zl.Sugar().With("TestName", tt.name).With("Reconcile", "cleanup"),
					clock:    cl,
				}

				if err := fc.Delete(t.Context(), pg); err != nil {
					t.Fatalf("error deleting ProxyGroup: %v", err)
				}

				expectReconciled(t, reconciler, "", pg.Name)
				expectMissing[tsapi.ProxyGroup](t, fc, "", pg.Name)

				if err := fc.Delete(t.Context(), pc); err != nil {
					t.Fatalf("error deleting ProxyClass: %v", err)
				}
				expectMissing[tsapi.ProxyClass](t, fc, "", pc.Name)
			})
		})
	}
}

func TestProxyGroup(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default-pc",
		},
		Spec: tsapi.ProxyClassSpec{
			StatefulSet: &tsapi.StatefulSet{
				Annotations: defaultProxyClassAnnotations,
			},
		},
	}
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Finalizers: []string{"tailscale.com/finalizer"},
			Generation: 1,
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeEgress,
		},
	}

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pg, pc).
		WithStatusSubresource(pg, pc).
		Build()
	tsClient := &fakeTSClient{}
	zl, _ := zap.NewDevelopment()
	fr := record.NewFakeRecorder(1)
	cl := tstest.NewClock(tstest.ClockOpts{})
	reconciler := &ProxyGroupReconciler{
		tsNamespace:       tsNamespace,
		tsProxyImage:      testProxyImage,
		defaultTags:       []string{"tag:test-tag"},
		tsFirewallMode:    "auto",
		defaultProxyClass: "default-pc",

		Client:   fc,
		tsClient: tsClient,
		recorder: fr,
		log:      zl.Sugar(),
		clock:    cl,
	}
	crd := &apiextensionsv1.CustomResourceDefinition{ObjectMeta: metav1.ObjectMeta{Name: serviceMonitorCRD}}
	opts := configOpts{
		proxyType:          "proxygroup",
		stsName:            pg.Name,
		parentType:         "proxygroup",
		tailscaleNamespace: "tailscale",
		resourceVersion:    "1",
	}

	t.Run("proxyclass_not_ready", func(t *testing.T) {
		expectReconciled(t, reconciler, "", pg.Name)

		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionFalse, reasonProxyGroupCreating, "0/2 ProxyGroup pods running", 0, cl, zl.Sugar())
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "the ProxyGroup's ProxyClass \"default-pc\" is not yet in a ready state, waiting...", 1, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, false, pc)
		if kube.ProxyGroupAvailable(pg) {
			t.Fatal("expected ProxyGroup to not be available")
		}
	})

	t.Run("observe_ProxyGroupCreating_status_reason", func(t *testing.T) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Type:               string(tsapi.ProxyClassReady),
				Status:             metav1.ConditionTrue,
				Reason:             reasonProxyClassValid,
				Message:            reasonProxyClassValid,
				LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
			}},
		}
		if err := fc.Status().Update(t.Context(), pc); err != nil {
			t.Fatal(err)
		}
		pg.ObjectMeta.Generation = 2
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.ObjectMeta.Generation = pg.ObjectMeta.Generation
		})
		expectReconciled(t, reconciler, "", pg.Name)

		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "0/2 ProxyGroup pods running", 2, cl, zl.Sugar())
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionFalse, reasonProxyGroupCreating, "0/2 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
		if kube.ProxyGroupAvailable(pg) {
			t.Fatal("expected ProxyGroup to not be available")
		}
		if expected := 1; reconciler.egressProxyGroups.Len() != expected {
			t.Fatalf("expected %d egress ProxyGroups, got %d", expected, reconciler.egressProxyGroups.Len())
		}
		expectProxyGroupResources(t, fc, pg, true, pc)
		keyReq := tailscale.KeyCapabilities{
			Devices: tailscale.KeyDeviceCapabilities{
				Create: tailscale.KeyDeviceCreateCapabilities{
					Reusable:      false,
					Ephemeral:     false,
					Preauthorized: true,
					Tags:          []string{"tag:test-tag"},
				},
			},
		}
		if diff := cmp.Diff(tsClient.KeyRequests(), []tailscale.KeyCapabilities{keyReq, keyReq}); diff != "" {
			t.Fatalf("unexpected secrets (-got +want):\n%s", diff)
		}
	})

	t.Run("simulate_successful_device_auth", func(t *testing.T) {
		addNodeIDToStateSecrets(t, fc, pg)
		pg.ObjectMeta.Generation = 3
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.ObjectMeta.Generation = pg.ObjectMeta.Generation
		})
		expectReconciled(t, reconciler, "", pg.Name)

		pg.Status.Devices = []tsapi.TailnetDevice{
			{
				Hostname:   "hostname-nodeid-0",
				TailnetIPs: []string{"1.2.3.4", "::1"},
			},
			{
				Hostname:   "hostname-nodeid-1",
				TailnetIPs: []string{"1.2.3.4", "::1"},
			},
		}
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady, 3, cl, zl.Sugar())
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, reasonProxyGroupAvailable, "2/2 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
		if !kube.ProxyGroupAvailable(pg) {
			t.Fatal("expected ProxyGroup to be available")
		}
	})

	t.Run("scale_up_to_3", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](3)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "2/3 ProxyGroup pods running", 3, cl, zl.Sugar())
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, reasonProxyGroupCreating, "2/3 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)

		addNodeIDToStateSecrets(t, fc, pg)
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady, 3, cl, zl.Sugar())
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, reasonProxyGroupAvailable, "3/3 ProxyGroup pods running", 0, cl, zl.Sugar())
		pg.Status.Devices = append(pg.Status.Devices, tsapi.TailnetDevice{
			Hostname:   "hostname-nodeid-2",
			TailnetIPs: []string{"1.2.3.4", "::1"},
		})
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
	})

	t.Run("scale_down_to_1", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](1)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})

		expectReconciled(t, reconciler, "", pg.Name)

		pg.Status.Devices = pg.Status.Devices[:1] // truncate to only the first device.
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, reasonProxyGroupAvailable, "1/1 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, pc)
	})

	t.Run("enable_metrics", func(t *testing.T) {
		pc.Spec.Metrics = &tsapi.Metrics{Enable: true}
		mustUpdate(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
			p.Spec = pc.Spec
		})
		expectReconciled(t, reconciler, "", pg.Name)
		expectEqual(t, fc, expectedMetricsService(opts))
	})
	t.Run("enable_service_monitor_no_crd", func(t *testing.T) {
		pc.Spec.Metrics.ServiceMonitor = &tsapi.ServiceMonitor{Enable: true}
		mustUpdate(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
			p.Spec.Metrics = pc.Spec.Metrics
		})
		expectReconciled(t, reconciler, "", pg.Name)
	})
	t.Run("create_crd_expect_service_monitor", func(t *testing.T) {
		mustCreate(t, fc, crd)
		expectReconciled(t, reconciler, "", pg.Name)
		expectEqualUnstructured(t, fc, expectedServiceMonitor(t, opts))
	})

	t.Run("delete_and_cleanup", func(t *testing.T) {
		if err := fc.Delete(t.Context(), pg); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)

		expectMissing[tsapi.ProxyGroup](t, fc, "", pg.Name)
		if expected := 0; reconciler.egressProxyGroups.Len() != expected {
			t.Fatalf("expected %d ProxyGroups, got %d", expected, reconciler.egressProxyGroups.Len())
		}
		// 2 nodes should get deleted as part of the scale down, and then finally
		// the first node gets deleted with the ProxyGroup cleanup.
		if diff := cmp.Diff(tsClient.deleted, []string{"nodeid-1", "nodeid-2", "nodeid-0"}); diff != "" {
			t.Fatalf("unexpected deleted devices (-got +want):\n%s", diff)
		}
		expectMissing[corev1.Service](t, reconciler, "tailscale", metricsResourceName(pg.Name))
		// The fake client does not clean up objects whose owner has been
		// deleted, so we can't test for the owned resources getting deleted.
	})
}

func TestProxyGroupTypes(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{},
	}
	// Passing ProxyGroup as status subresource is a way to get around fake
	// client's limitations for updating resource statuses.
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc).
		WithStatusSubresource(pc, &tsapi.ProxyGroup{}).
		Build()
	mustUpdateStatus(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
		p.Status.Conditions = []metav1.Condition{{
			Type:               string(tsapi.ProxyClassReady),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: 1,
		}}
	})

	zl, _ := zap.NewDevelopment()
	reconciler := &ProxyGroupReconciler{
		tsNamespace:  tsNamespace,
		tsProxyImage: testProxyImage,
		Client:       fc,
		log:          zl.Sugar(),
		tsClient:     &fakeTSClient{},
		clock:        tstest.NewClock(tstest.ClockOpts{}),
	}

	t.Run("egress_type", func(t *testing.T) {
		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-egress",
				UID:  "test-egress-uid",
			},
			Spec: tsapi.ProxyGroupSpec{
				Type:     tsapi.ProxyGroupTypeEgress,
				Replicas: ptr.To[int32](0),
			},
		}
		mustCreate(t, fc, pg)

		expectReconciled(t, reconciler, "", pg.Name)
		verifyProxyGroupCounts(t, reconciler, 0, 1, 0)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}
		verifyEnvVar(t, sts, "TS_INTERNAL_APP", kubetypes.AppProxyGroupEgress)
		verifyEnvVar(t, sts, "TS_EGRESS_PROXIES_CONFIG_PATH", "/etc/proxies")
		verifyEnvVar(t, sts, "TS_ENABLE_HEALTH_CHECK", "true")

		// Verify that egress configuration has been set up.
		cm := &corev1.ConfigMap{}
		cmName := fmt.Sprintf("%s-egress-config", pg.Name)
		if err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: cmName}, cm); err != nil {
			t.Fatalf("failed to get ConfigMap: %v", err)
		}

		expectedVolumes := []corev1.Volume{
			{
				Name: cmName,
				VolumeSource: corev1.VolumeSource{
					ConfigMap: &corev1.ConfigMapVolumeSource{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: cmName,
						},
					},
				},
			},
		}

		expectedVolumeMounts := []corev1.VolumeMount{
			{
				Name:      cmName,
				MountPath: "/etc/proxies",
				ReadOnly:  true,
			},
		}

		if diff := cmp.Diff(expectedVolumes, sts.Spec.Template.Spec.Volumes); diff != "" {
			t.Errorf("unexpected volumes (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff(expectedVolumeMounts, sts.Spec.Template.Spec.Containers[0].VolumeMounts); diff != "" {
			t.Errorf("unexpected volume mounts (-want +got):\n%s", diff)
		}

		expectedLifecycle := corev1.Lifecycle{
			PreStop: &corev1.LifecycleHandler{
				HTTPGet: &corev1.HTTPGetAction{
					Path: kubetypes.EgessServicesPreshutdownEP,
					Port: intstr.FromInt(defaultLocalAddrPort),
				},
			},
		}
		if diff := cmp.Diff(expectedLifecycle, *sts.Spec.Template.Spec.Containers[0].Lifecycle); diff != "" {
			t.Errorf("unexpected lifecycle (-want +got):\n%s", diff)
		}
		if *sts.Spec.Template.DeletionGracePeriodSeconds != deletionGracePeriodSeconds {
			t.Errorf("unexpected deletion grace period seconds %d, want %d", *sts.Spec.Template.DeletionGracePeriodSeconds, deletionGracePeriodSeconds)
		}
	})
	t.Run("egress_type_no_lifecycle_hook_when_local_addr_port_set", func(t *testing.T) {
		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-egress-no-lifecycle",
				UID:  "test-egress-no-lifecycle-uid",
			},
			Spec: tsapi.ProxyGroupSpec{
				Type:       tsapi.ProxyGroupTypeEgress,
				Replicas:   ptr.To[int32](0),
				ProxyClass: "test",
			},
		}
		mustCreate(t, fc, pg)
		mustUpdate(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
			p.Spec.StatefulSet = &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleContainer: &tsapi.Container{
						Env: []tsapi.Env{{
							Name:  "TS_LOCAL_ADDR_PORT",
							Value: "127.0.0.1:8080",
						}},
					},
				},
			}
		})
		expectReconciled(t, reconciler, "", pg.Name)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}

		if sts.Spec.Template.Spec.Containers[0].Lifecycle != nil {
			t.Error("lifecycle hook was set when TS_LOCAL_ADDR_PORT was configured via ProxyClass")
		}
	})

	t.Run("ingress_type", func(t *testing.T) {
		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-ingress",
				UID:  "test-ingress-uid",
			},
			Spec: tsapi.ProxyGroupSpec{
				Type:     tsapi.ProxyGroupTypeIngress,
				Replicas: ptr.To[int32](0),
			},
		}
		if err := fc.Create(t.Context(), pg); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)
		verifyProxyGroupCounts(t, reconciler, 1, 2, 0)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}
		verifyEnvVar(t, sts, "TS_INTERNAL_APP", kubetypes.AppProxyGroupIngress)
		verifyEnvVar(t, sts, "TS_SERVE_CONFIG", "/etc/proxies/serve-config.json")
		verifyEnvVar(t, sts, "TS_EXPERIMENTAL_CERT_SHARE", "true")

		// Verify ConfigMap volume mount
		cmName := fmt.Sprintf("%s-ingress-config", pg.Name)
		expectedVolume := corev1.Volume{
			Name: cmName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cmName,
					},
				},
			},
		}

		expectedVolumeMount := corev1.VolumeMount{
			Name:      cmName,
			MountPath: "/etc/proxies",
			ReadOnly:  true,
		}

		if diff := cmp.Diff([]corev1.Volume{expectedVolume}, sts.Spec.Template.Spec.Volumes); diff != "" {
			t.Errorf("unexpected volumes (-want +got):\n%s", diff)
		}

		if diff := cmp.Diff([]corev1.VolumeMount{expectedVolumeMount}, sts.Spec.Template.Spec.Containers[0].VolumeMounts); diff != "" {
			t.Errorf("unexpected volume mounts (-want +got):\n%s", diff)
		}
	})

	t.Run("kubernetes_api_server_type", func(t *testing.T) {
		pg := &tsapi.ProxyGroup{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-k8s-apiserver",
				UID:  "test-k8s-apiserver-uid",
			},
			Spec: tsapi.ProxyGroupSpec{
				Type:     tsapi.ProxyGroupTypeKubernetesAPIServer,
				Replicas: ptr.To[int32](2),
				KubeAPIServer: &tsapi.KubeAPIServerConfig{
					Mode: ptr.To(tsapi.APIServerProxyModeNoAuth),
				},
			},
		}
		if err := fc.Create(t.Context(), pg); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)
		verifyProxyGroupCounts(t, reconciler, 1, 2, 1)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}

		// Verify the StatefulSet configuration for KubernetesAPIServer type.
		if sts.Spec.Template.Spec.Containers[0].Name != mainContainerName {
			t.Errorf("unexpected container name %s, want %s", sts.Spec.Template.Spec.Containers[0].Name, mainContainerName)
		}
		if sts.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort != 443 {
			t.Errorf("unexpected container port %d, want 443", sts.Spec.Template.Spec.Containers[0].Ports[0].ContainerPort)
		}
		if sts.Spec.Template.Spec.Containers[0].Ports[0].Name != "k8s-proxy" {
			t.Errorf("unexpected port name %s, want k8s-proxy", sts.Spec.Template.Spec.Containers[0].Ports[0].Name)
		}
	})
}

func TestKubeAPIServerStatusConditionFlow(t *testing.T) {
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-k8s-apiserver",
			UID:        "test-k8s-apiserver-uid",
			Generation: 1,
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:     tsapi.ProxyGroupTypeKubernetesAPIServer,
			Replicas: ptr.To[int32](1),
			KubeAPIServer: &tsapi.KubeAPIServerConfig{
				Mode: ptr.To(tsapi.APIServerProxyModeNoAuth),
			},
		},
	}
	stateSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pgStateSecretName(pg.Name, 0),
			Namespace: tsNamespace,
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pg, stateSecret).
		WithStatusSubresource(pg).
		Build()
	r := &ProxyGroupReconciler{
		tsNamespace:  tsNamespace,
		tsProxyImage: testProxyImage,
		Client:       fc,
		log:          zap.Must(zap.NewDevelopment()).Sugar(),
		tsClient:     &fakeTSClient{},
		clock:        tstest.NewClock(tstest.ClockOpts{}),
	}

	expectReconciled(t, r, "", pg.Name)
	pg.ObjectMeta.Finalizers = append(pg.ObjectMeta.Finalizers, FinalizerName)
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionFalse, reasonProxyGroupCreating, "", 0, r.clock, r.log)
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "", 1, r.clock, r.log)
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)

	// Set kube-apiserver valid.
	mustUpdateStatus(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
		tsoperator.SetProxyGroupCondition(p, tsapi.KubeAPIServerProxyValid, metav1.ConditionTrue, reasonKubeAPIServerProxyValid, "", 1, r.clock, r.log)
	})
	expectReconciled(t, r, "", pg.Name)
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyValid, metav1.ConditionTrue, reasonKubeAPIServerProxyValid, "", 1, r.clock, r.log)
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "", 1, r.clock, r.log)
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)

	// Set available.
	addNodeIDToStateSecrets(t, fc, pg)
	expectReconciled(t, r, "", pg.Name)
	pg.Status.Devices = []tsapi.TailnetDevice{
		{
			Hostname:   "hostname-nodeid-0",
			TailnetIPs: []string{"1.2.3.4", "::1"},
		},
	}
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupAvailable, metav1.ConditionTrue, reasonProxyGroupAvailable, "", 0, r.clock, r.log)
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "", 1, r.clock, r.log)
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)

	// Set kube-apiserver configured.
	mustUpdateStatus(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
		tsoperator.SetProxyGroupCondition(p, tsapi.KubeAPIServerProxyConfigured, metav1.ConditionTrue, reasonKubeAPIServerProxyConfigured, "", 1, r.clock, r.log)
	})
	expectReconciled(t, r, "", pg.Name)
	tsoperator.SetProxyGroupCondition(pg, tsapi.KubeAPIServerProxyConfigured, metav1.ConditionTrue, reasonKubeAPIServerProxyConfigured, "", 1, r.clock, r.log)
	tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, "", 1, r.clock, r.log)
	expectEqual(t, fc, pg, omitPGStatusConditionMessages)
}

func TestKubeAPIServerType_DoesNotOverwriteServicesConfig(t *testing.T) {
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.ProxyGroup{}).
		Build()

	reconciler := &ProxyGroupReconciler{
		tsNamespace:  tsNamespace,
		tsProxyImage: testProxyImage,
		Client:       fc,
		log:          zap.Must(zap.NewDevelopment()).Sugar(),
		tsClient:     &fakeTSClient{},
		clock:        tstest.NewClock(tstest.ClockOpts{}),
	}

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-k8s-apiserver",
			UID:  "test-k8s-apiserver-uid",
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:     tsapi.ProxyGroupTypeKubernetesAPIServer,
			Replicas: ptr.To[int32](1),
			KubeAPIServer: &tsapi.KubeAPIServerConfig{
				Mode: ptr.To(tsapi.APIServerProxyModeNoAuth), // Avoid needing to pre-create the static ServiceAccount.
			},
		},
	}
	if err := fc.Create(t.Context(), pg); err != nil {
		t.Fatal(err)
	}
	expectReconciled(t, reconciler, "", pg.Name)

	cfg := conf.VersionedConfig{
		Version: "v1alpha1",
		ConfigV1Alpha1: &conf.ConfigV1Alpha1{
			AuthKey:  ptr.To("secret-authkey"),
			State:    ptr.To(fmt.Sprintf("kube:%s", pgPodName(pg.Name, 0))),
			App:      ptr.To(kubetypes.AppProxyGroupKubeAPIServer),
			LogLevel: ptr.To("debug"),

			Hostname: ptr.To("test-k8s-apiserver-0"),
			APIServerProxy: &conf.APIServerProxyConfig{
				Enabled:    opt.NewBool(true),
				Mode:       ptr.To(kubetypes.APIServerProxyModeNoAuth),
				IssueCerts: opt.NewBool(true),
			},
			LocalPort:          ptr.To(uint16(9002)),
			HealthCheckEnabled: opt.NewBool(true),
		},
	}
	cfgB, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	cfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pgConfigSecretName(pg.Name, 0),
			Namespace:       tsNamespace,
			Labels:          pgSecretLabels(pg.Name, kubetypes.LabelSecretTypeConfig),
			OwnerReferences: pgOwnerReference(pg),
		},
		Data: map[string][]byte{
			kubetypes.KubeAPIServerConfigFile: cfgB,
		},
	}
	expectEqual(t, fc, cfgSecret)

	// Now simulate the kube-apiserver services reconciler updating config,
	// then check the proxygroup reconciler doesn't overwrite it.
	cfg.APIServerProxy.ServiceName = ptr.To(tailcfg.ServiceName("svc:some-svc-name"))
	cfg.AdvertiseServices = []string{"svc:should-not-be-overwritten"}
	cfgB, err = json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	mustUpdate(t, fc, tsNamespace, cfgSecret.Name, func(s *corev1.Secret) {
		s.Data[kubetypes.KubeAPIServerConfigFile] = cfgB
	})
	expectReconciled(t, reconciler, "", pg.Name)

	cfgSecret.Data[kubetypes.KubeAPIServerConfigFile] = cfgB
	expectEqual(t, fc, cfgSecret)
}

func TestIngressAdvertiseServicesConfigPreserved(t *testing.T) {
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithStatusSubresource(&tsapi.ProxyGroup{}).
		Build()
	reconciler := &ProxyGroupReconciler{
		tsNamespace:  tsNamespace,
		tsProxyImage: testProxyImage,
		Client:       fc,
		log:          zap.Must(zap.NewDevelopment()).Sugar(),
		tsClient:     &fakeTSClient{},
		clock:        tstest.NewClock(tstest.ClockOpts{}),
	}

	existingServices := []string{"svc1", "svc2"}
	existingConfigBytes, err := json.Marshal(ipn.ConfigVAlpha{
		AdvertiseServices: existingServices,
		Version:           "should-get-overwritten",
	})
	if err != nil {
		t.Fatal(err)
	}

	const pgName = "test-ingress"
	mustCreate(t, fc, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pgConfigSecretName(pgName, 0),
			Namespace: tsNamespace,
		},
		Data: map[string][]byte{
			tsoperator.TailscaledConfigFileName(pgMinCapabilityVersion): existingConfigBytes,
		},
	})

	mustCreate(t, fc, &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: pgName,
			UID:  "test-ingress-uid",
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:     tsapi.ProxyGroupTypeIngress,
			Replicas: ptr.To[int32](1),
		},
	})
	expectReconciled(t, reconciler, "", pgName)

	expectedConfigBytes, err := json.Marshal(ipn.ConfigVAlpha{
		// Preserved.
		AdvertiseServices: existingServices,

		// Everything else got updated in the reconcile:
		Version:      "alpha0",
		AcceptDNS:    "false",
		AcceptRoutes: "false",
		Locked:       "false",
		Hostname:     ptr.To(fmt.Sprintf("%s-%d", pgName, 0)),
	})
	if err != nil {
		t.Fatal(err)
	}
	expectEqual(t, fc, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            pgConfigSecretName(pgName, 0),
			Namespace:       tsNamespace,
			ResourceVersion: "2",
		},
		Data: map[string][]byte{
			tsoperator.TailscaledConfigFileName(pgMinCapabilityVersion): expectedConfigBytes,
		},
	})
}

func TestValidateProxyGroup(t *testing.T) {
	type testCase struct {
		typ            tsapi.ProxyGroupType
		pgName         string
		image          string
		noauth         bool
		initContainer  bool
		staticSAExists bool
		expectedErrs   int
	}

	for name, tc := range map[string]testCase{
		"default_ingress": {
			typ: tsapi.ProxyGroupTypeIngress,
		},
		"default_kube": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: true,
		},
		"default_kube_noauth": {
			typ:    tsapi.ProxyGroupTypeKubernetesAPIServer,
			noauth: true,
			// Does not require the static ServiceAccount to exist.
		},
		"kube_static_sa_missing": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: false,
			expectedErrs:   1,
		},
		"kube_noauth_would_overwrite_static_sa": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: true,
			noauth:         true,
			pgName:         authAPIServerProxySAName,
			expectedErrs:   1,
		},
		"ingress_would_overwrite_static_sa": {
			typ:            tsapi.ProxyGroupTypeIngress,
			staticSAExists: true,
			pgName:         authAPIServerProxySAName,
			expectedErrs:   1,
		},
		"tailscale_image_for_kube_pg_1": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: true,
			image:          "example.com/tailscale/tailscale",
			expectedErrs:   1,
		},
		"tailscale_image_for_kube_pg_2": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: true,
			image:          "example.com/tailscale",
			expectedErrs:   1,
		},
		"tailscale_image_for_kube_pg_3": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: true,
			image:          "example.com/tailscale/tailscale:latest",
			expectedErrs:   1,
		},
		"tailscale_image_for_kube_pg_4": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: true,
			image:          "tailscale/tailscale",
			expectedErrs:   1,
		},
		"k8s_proxy_image_for_ingress_pg": {
			typ:          tsapi.ProxyGroupTypeIngress,
			image:        "example.com/k8s-proxy",
			expectedErrs: 1,
		},
		"init_container_for_kube_pg": {
			typ:            tsapi.ProxyGroupTypeKubernetesAPIServer,
			staticSAExists: true,
			initContainer:  true,
			expectedErrs:   1,
		},
		"init_container_for_ingress_pg": {
			typ:           tsapi.ProxyGroupTypeIngress,
			initContainer: true,
		},
		"init_container_for_egress_pg": {
			typ:           tsapi.ProxyGroupTypeEgress,
			initContainer: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			pc := &tsapi.ProxyClass{
				ObjectMeta: metav1.ObjectMeta{
					Name: "some-pc",
				},
				Spec: tsapi.ProxyClassSpec{
					StatefulSet: &tsapi.StatefulSet{
						Pod: &tsapi.Pod{},
					},
				},
			}
			if tc.image != "" {
				pc.Spec.StatefulSet.Pod.TailscaleContainer = &tsapi.Container{
					Image: tc.image,
				}
			}
			if tc.initContainer {
				pc.Spec.StatefulSet.Pod.TailscaleInitContainer = &tsapi.Container{}
			}
			pgName := "some-pg"
			if tc.pgName != "" {
				pgName = tc.pgName
			}
			pg := &tsapi.ProxyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: pgName,
				},
				Spec: tsapi.ProxyGroupSpec{
					Type: tc.typ,
				},
			}
			if tc.noauth {
				pg.Spec.KubeAPIServer = &tsapi.KubeAPIServerConfig{
					Mode: ptr.To(tsapi.APIServerProxyModeNoAuth),
				}
			}

			var objs []client.Object
			if tc.staticSAExists {
				objs = append(objs, &corev1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      authAPIServerProxySAName,
						Namespace: tsNamespace,
					},
				})
			}
			r := ProxyGroupReconciler{
				tsNamespace: tsNamespace,
				Client: fake.NewClientBuilder().
					WithObjects(objs...).
					Build(),
			}

			logger, _ := zap.NewDevelopment()
			err := r.validate(t.Context(), pg, pc, logger.Sugar())
			if tc.expectedErrs == 0 {
				if err != nil {
					t.Fatalf("expected no errors, got: %v", err)
				}
				// Test finished.
				return
			}

			if err == nil {
				t.Fatalf("expected %d errors, got none", tc.expectedErrs)
			}

			type unwrapper interface {
				Unwrap() []error
			}
			errs := err.(unwrapper)
			if len(errs.Unwrap()) != tc.expectedErrs {
				t.Fatalf("expected %d errors, got %d: %v", tc.expectedErrs, len(errs.Unwrap()), err)
			}
		})
	}
}

func proxyClassesForLEStagingTest() (*tsapi.ProxyClass, *tsapi.ProxyClass, *tsapi.ProxyClass) {
	pcLEStaging := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "le-staging",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: true,
		},
	}

	pcLEStagingFalse := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "le-staging-false",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: false,
		},
	}

	pcOther := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "other",
			Generation: 1,
		},
		Spec: tsapi.ProxyClassSpec{},
	}

	return pcLEStaging, pcLEStagingFalse, pcOther
}

func setProxyClassReady(t *testing.T, fc client.Client, cl *tstest.Clock, name string) *tsapi.ProxyClass {
	t.Helper()
	pc := &tsapi.ProxyClass{}
	if err := fc.Get(t.Context(), client.ObjectKey{Name: name}, pc); err != nil {
		t.Fatal(err)
	}
	pc.Status = tsapi.ProxyClassStatus{
		Conditions: []metav1.Condition{{
			Type:               string(tsapi.ProxyClassReady),
			Status:             metav1.ConditionTrue,
			Reason:             reasonProxyClassValid,
			Message:            reasonProxyClassValid,
			LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
			ObservedGeneration: pc.Generation,
		}},
	}
	if err := fc.Status().Update(t.Context(), pc); err != nil {
		t.Fatal(err)
	}
	return pc
}

func verifyProxyGroupCounts(t *testing.T, r *ProxyGroupReconciler, wantIngress, wantEgress, wantAPIServer int) {
	t.Helper()
	if r.ingressProxyGroups.Len() != wantIngress {
		t.Errorf("expected %d ingress proxy groups, got %d", wantIngress, r.ingressProxyGroups.Len())
	}
	if r.egressProxyGroups.Len() != wantEgress {
		t.Errorf("expected %d egress proxy groups, got %d", wantEgress, r.egressProxyGroups.Len())
	}
	if r.apiServerProxyGroups.Len() != wantAPIServer {
		t.Errorf("expected %d kube-apiserver proxy groups, got %d", wantAPIServer, r.apiServerProxyGroups.Len())
	}
}

func verifyEnvVar(t *testing.T, sts *appsv1.StatefulSet, name, expectedValue string) {
	t.Helper()
	for _, env := range sts.Spec.Template.Spec.Containers[0].Env {
		if env.Name == name {
			if env.Value != expectedValue {
				t.Errorf("expected %s=%s, got %s", name, expectedValue, env.Value)
			}
			return
		}
	}
	t.Errorf("%s environment variable not found", name)
}

func verifyEnvVarNotPresent(t *testing.T, sts *appsv1.StatefulSet, name string) {
	t.Helper()
	for _, env := range sts.Spec.Template.Spec.Containers[0].Env {
		if env.Name == name {
			t.Errorf("environment variable %s should not be present", name)
			return
		}
	}
}

func expectProxyGroupResources(t *testing.T, fc client.WithWatch, pg *tsapi.ProxyGroup, shouldExist bool, proxyClass *tsapi.ProxyClass) {
	t.Helper()

	role := pgRole(pg, tsNamespace)
	roleBinding := pgRoleBinding(pg, tsNamespace)
	serviceAccount := pgServiceAccount(pg, tsNamespace)
	statefulSet, err := pgStatefulSet(pg, tsNamespace, testProxyImage, "auto", nil, proxyClass)
	if err != nil {
		t.Fatal(err)
	}
	statefulSet.Annotations = defaultProxyClassAnnotations

	if shouldExist {
		expectEqual(t, fc, role)
		expectEqual(t, fc, roleBinding)
		expectEqual(t, fc, serviceAccount)
		expectEqual(t, fc, statefulSet, removeResourceReqs)
	} else {
		expectMissing[rbacv1.Role](t, fc, role.Namespace, role.Name)
		expectMissing[rbacv1.RoleBinding](t, fc, roleBinding.Namespace, roleBinding.Name)
		expectMissing[corev1.ServiceAccount](t, fc, serviceAccount.Namespace, serviceAccount.Name)
		expectMissing[appsv1.StatefulSet](t, fc, statefulSet.Namespace, statefulSet.Name)
	}

	var expectedSecrets []string
	if shouldExist {
		for i := range pgReplicas(pg) {
			expectedSecrets = append(expectedSecrets,
				fmt.Sprintf("%s-%d", pg.Name, i),
				pgConfigSecretName(pg.Name, i),
			)
		}
	}
	expectSecrets(t, fc, expectedSecrets)
}

func expectSecrets(t *testing.T, fc client.WithWatch, expected []string) {
	t.Helper()

	secrets := &corev1.SecretList{}
	if err := fc.List(t.Context(), secrets); err != nil {
		t.Fatal(err)
	}

	var actual []string
	for _, secret := range secrets.Items {
		actual = append(actual, secret.Name)
	}

	if diff := cmp.Diff(actual, expected); diff != "" {
		t.Fatalf("unexpected secrets (-got +want):\n%s", diff)
	}
}

func addNodeIDToStateSecrets(t *testing.T, fc client.WithWatch, pg *tsapi.ProxyGroup) {
	t.Helper()
	const key = "profile-abc"
	for i := range pgReplicas(pg) {
		bytes, err := json.Marshal(map[string]any{
			"Config": map[string]any{
				"NodeID": fmt.Sprintf("nodeid-%d", i),
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		podUID := fmt.Sprintf("pod-uid-%d", i)
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("%s-%d", pg.Name, i),
				Namespace: "tailscale",
				UID:       types.UID(podUID),
			},
		}
		if _, err := createOrUpdate(t.Context(), fc, "tailscale", pod, nil); err != nil {
			t.Fatalf("failed to create or update Pod %s: %v", pod.Name, err)
		}
		mustUpdate(t, fc, tsNamespace, pgStateSecretName(pg.Name, i), func(s *corev1.Secret) {
			s.Data = map[string][]byte{
				currentProfileKey:       []byte(key),
				key:                     bytes,
				kubetypes.KeyDeviceIPs:  []byte(`["1.2.3.4", "::1"]`),
				kubetypes.KeyDeviceFQDN: []byte(fmt.Sprintf("hostname-nodeid-%d.tails-scales.ts.net", i)),
				// TODO(tomhjp): We have two different mechanisms to retrieve device IDs.
				// Consolidate on this one.
				kubetypes.KeyDeviceID: []byte(fmt.Sprintf("nodeid-%d", i)),
				kubetypes.KeyPodUID:   []byte(podUID),
			}
		})
	}
}

func TestProxyGroupLetsEncryptStaging(t *testing.T) {
	cl := tstest.NewClock(tstest.ClockOpts{})
	zl := zap.Must(zap.NewDevelopment())

	// Set up test cases- most are shared with non-HA Ingress.
	type proxyGroupLETestCase struct {
		leStagingTestCase
		pgType tsapi.ProxyGroupType
	}
	pcLEStaging, pcLEStagingFalse, pcOther := proxyClassesForLEStagingTest()
	sharedTestCases := testCasesForLEStagingTests()
	var tests []proxyGroupLETestCase
	for _, tt := range sharedTestCases {
		tests = append(tests, proxyGroupLETestCase{
			leStagingTestCase: tt,
			pgType:            tsapi.ProxyGroupTypeIngress,
		})
	}
	tests = append(tests, proxyGroupLETestCase{
		leStagingTestCase: leStagingTestCase{
			name:                  "egress_pg_with_staging_proxyclass",
			proxyClassPerResource: "le-staging",
			useLEStagingEndpoint:  false,
		},
		pgType: tsapi.ProxyGroupTypeEgress,
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().
				WithScheme(tsapi.GlobalScheme)

			pg := &tsapi.ProxyGroup{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test",
				},
				Spec: tsapi.ProxyGroupSpec{
					Type:       tt.pgType,
					Replicas:   ptr.To[int32](1),
					ProxyClass: tt.proxyClassPerResource,
				},
			}

			// Pre-populate the fake client with ProxyClasses.
			builder = builder.WithObjects(pcLEStaging, pcLEStagingFalse, pcOther, pg).
				WithStatusSubresource(pcLEStaging, pcLEStagingFalse, pcOther, pg)

			fc := builder.Build()

			// If the test case needs a ProxyClass to exist, ensure it is set to Ready.
			if tt.proxyClassPerResource != "" || tt.defaultProxyClass != "" {
				name := tt.proxyClassPerResource
				if name == "" {
					name = tt.defaultProxyClass
				}
				setProxyClassReady(t, fc, cl, name)
			}

			reconciler := &ProxyGroupReconciler{
				tsNamespace:       tsNamespace,
				tsProxyImage:      testProxyImage,
				defaultTags:       []string{"tag:test"},
				defaultProxyClass: tt.defaultProxyClass,
				Client:            fc,
				tsClient:          &fakeTSClient{},
				log:               zl.Sugar(),
				clock:             cl,
			}

			expectReconciled(t, reconciler, "", pg.Name)

			// Verify that the StatefulSet created for ProxyGrup has
			// the expected setting for the staging endpoint.
			sts := &appsv1.StatefulSet{}
			if err := fc.Get(t.Context(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
				t.Fatalf("failed to get StatefulSet: %v", err)
			}

			if tt.useLEStagingEndpoint {
				verifyEnvVar(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL", letsEncryptStagingEndpoint)
			} else {
				verifyEnvVarNotPresent(t, sts, "TS_DEBUG_ACME_DIRECTORY_URL")
			}
		})
	}
}

type leStagingTestCase struct {
	name string
	// ProxyClass set on ProxyGroup or Ingress resource.
	proxyClassPerResource string
	// Default ProxyClass.
	defaultProxyClass    string
	useLEStagingEndpoint bool
}

// Shared test cases for LE staging endpoint configuration for ProxyGroup and
// non-HA Ingress.
func testCasesForLEStagingTests() []leStagingTestCase {
	return []leStagingTestCase{
		{
			name:                  "with_staging_proxyclass",
			proxyClassPerResource: "le-staging",
			useLEStagingEndpoint:  true,
		},
		{
			name:                  "with_staging_proxyclass_false",
			proxyClassPerResource: "le-staging-false",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "with_other_proxyclass",
			proxyClassPerResource: "other",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "no_proxyclass",
			proxyClassPerResource: "",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "with_default_staging_proxyclass",
			proxyClassPerResource: "",
			defaultProxyClass:     "le-staging",
			useLEStagingEndpoint:  true,
		},
		{
			name:                  "with_default_other_proxyclass",
			proxyClassPerResource: "",
			defaultProxyClass:     "other",
			useLEStagingEndpoint:  false,
		},
		{
			name:                  "with_default_staging_proxyclass_false",
			proxyClassPerResource: "",
			defaultProxyClass:     "le-staging-false",
			useLEStagingEndpoint:  false,
		},
	}
}
