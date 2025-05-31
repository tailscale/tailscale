// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

const (
	testProxyImage = "tailscale/tailscale:test"
	initialCfgHash = "6632726be70cf224049580deb4d317bba065915b5fd415461d60ed621c91b196"
)

var defaultProxyClassAnnotations = map[string]string{
	"some-annotation": "from-the-proxy-class",
}

func TestProxyGroupWithStaticEndpoints(t *testing.T) {
	type testNode struct {
		name   string
		ips    []string
		labels map[string]string
	}

	testCases := []struct {
		name                  string
		listenerConfig        *tsapi.TailnetListenerConfig
		replicas              *int32
		nodes                 []testNode
		expectStaticEndpoints bool
		expectErrOnReconcile  bool
	}{
		{
			name: "PortsAutoAllocated",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(3)),
			nodes: []testNode{
				{
					name: "foobar",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbaz",
					ips:  []string{"192.168.0.2"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbazz",
					ips:  []string{"192.168.0.3"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			expectStaticEndpoints: true,
			expectErrOnReconcile:  false,
		},
		{
			name: "InvalidType",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "BlumBlum",
				NodePortConfig: &tsapi.NodePort{
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(4)),
			nodes: []testNode{
				{
					name: "foobar",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbaz",
					ips:  []string{"192.168.0.2"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbazz",
					ips:  []string{"192.168.0.3"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			expectStaticEndpoints: false,
			expectErrOnReconcile:  false,
		},
		{
			name: "SpecificPorts",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"3001", "3005", "3007", "3009"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(4)),
			nodes: []testNode{
				{
					name: "foobar",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbaz",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbazz",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			expectStaticEndpoints: true,
			expectErrOnReconcile:  false,
		},
		{
			name: "NotEnoughPorts",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"3001", "3005"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(4)),
			nodes: []testNode{
				{
					name: "foobar",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbaz",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbazz",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			expectStaticEndpoints: false,
			expectErrOnReconcile:  true,
		},
		{
			name: "InvalidPortString",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"abcd", "3005", "3007", "3009"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(4)),
			nodes: []testNode{
				{
					name: "foobar",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbaz",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbazz",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			expectStaticEndpoints: false,
			expectErrOnReconcile:  true,
		},
		{
			name: "NonClashingRanges",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"3000-3002", "3003-3005", "3006"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(3)),
			nodes: []testNode{
				{name: "node1", ips: []string{"10.0.0.1"}, labels: map[string]string{"foo/bar": "baz"}},
				{name: "node2", ips: []string{"10.0.0.2"}, labels: map[string]string{"foo/bar": "baz"}},
				{name: "node3", ips: []string{"10.0.0.3"}, labels: map[string]string{"foo/bar": "baz"}},
			},
			expectStaticEndpoints: true,
			expectErrOnReconcile:  false,
		},
		{
			name: "SingleValidPorts",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"3100", "3101", "3102"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(3)),
			nodes: []testNode{
				{name: "node1", ips: []string{"10.0.0.1"}, labels: map[string]string{"foo/bar": "baz"}},
				{name: "node2", ips: []string{"10.0.0.2"}, labels: map[string]string{"foo/bar": "baz"}},
				{name: "node3", ips: []string{"10.0.0.3"}, labels: map[string]string{"foo/bar": "baz"}},
			},
			expectStaticEndpoints: true,
			expectErrOnReconcile:  false,
		},
		{
			name: "OverlappingPortRanges",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"1000-2000", "1500-1800"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(3)),
			nodes: []testNode{
				{name: "node1", ips: []string{"10.0.0.1"}, labels: map[string]string{"foo/bar": "baz"}},
				{name: "node2", ips: []string{"10.0.0.2"}, labels: map[string]string{"foo/bar": "baz"}},
				{name: "node3", ips: []string{"10.0.0.3"}, labels: map[string]string{"foo/bar": "baz"}},
			},
			expectStaticEndpoints: false,
			expectErrOnReconcile:  true,
		},
		{
			name: "ClashingRanges",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"3005", "3007", "3009", "3001-3010"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(4)),
			nodes: []testNode{
				{
					name: "foobar",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbaz",
					ips:  []string{"192.168.0.2"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
				{
					name: "foobarbazz",
					ips:  []string{"192.168.0.3"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			expectStaticEndpoints: false,
			expectErrOnReconcile:  true,
		},
		{
			name: "MalformedPortRange",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"3000-30a0", "3050"},
					Selector: map[string]string{
						"foo/bar": "baz",
					},
				},
			},
			replicas: ptr.To(int32(2)),
			nodes: []testNode{
				{name: "node1", ips: []string{"10.0.0.1"}, labels: map[string]string{"foo/bar": "baz"}},
				{name: "node2", ips: []string{"10.0.0.2"}, labels: map[string]string{"foo/bar": "baz"}},
			},
			expectStaticEndpoints: false,
			expectErrOnReconcile:  true,
		},
		{
			name: "NoMatchingNodes",
			listenerConfig: &tsapi.TailnetListenerConfig{
				Type: "NodePort",
				NodePortConfig: &tsapi.NodePort{
					PortRanges: []string{"3000-3005"},
					Selector: map[string]string{
						"zone": "us-west",
					},
				},
			},
			replicas: ptr.To(int32(2)),
			nodes: []testNode{
				{name: "node1", ips: []string{"10.0.0.1"}, labels: map[string]string{"zone": "eu-central"}},
				{name: "node2", ips: []string{"10.0.0.2"}, labels: map[string]string{"zone": "eu-central"}},
			},
			expectStaticEndpoints: false,
			expectErrOnReconcile:  true,
		},
	}

	for _, tt := range testCases {
		tsClient := &fakeTSClient{}
		zl, _ := zap.NewDevelopment()
		fr := record.NewFakeRecorder(1)
		cl := tstest.NewClock(tstest.ClockOpts{})
		t.Logf("Running TestCase %q", tt.name)
		pc := &tsapi.ProxyClass{
			ObjectMeta: metav1.ObjectMeta{
				Name: "default-pc",
			},
			Spec: tsapi.ProxyClassSpec{
				StatefulSet: &tsapi.StatefulSet{
					Annotations: defaultProxyClassAnnotations,
				},
				TailnetListenerConfig: tt.listenerConfig,
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
				Replicas:   tt.replicas,
			},
		}

		fc := fake.NewClientBuilder().
			WithScheme(tsapi.GlobalScheme).
			WithObjects(pg, pc).
			WithStatusSubresource(pg, pc).
			Build()

		ppc := &tsapi.ProxyClass{}
		_ = fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: "default-pc"}, ppc)

		if len(tt.nodes) == 0 {
			tt.nodes = []testNode{
				{
					name: "test-123",
					ips:  []string{"192.168.0.1"},
					labels: map[string]string{
						"foo/bar": "baz",
					},
				},
			}
		}

		expectedIPs := []string{}
		expectedPorts := []string{}
		if len(tt.listenerConfig.NodePortConfig.PortRanges) > 0 {
			expectedPorts = tt.listenerConfig.NodePortConfig.PortRanges
		}

		for _, n := range tt.nodes {
			for k, v := range tt.listenerConfig.NodePortConfig.Selector {
				if va, ok := n.labels[k]; ok && v == va {
					expectedIPs = append(expectedIPs, n.ips...)
				}
			}

			no := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{
					Name:   n.name,
					Labels: n.labels,
				},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{},
				},
			}

			for _, ip := range n.ips {
				no.Status.Addresses = append(no.Status.Addresses, corev1.NodeAddress{
					Type:    corev1.NodeExternalIP,
					Address: ip,
				})
			}

			fc.Create(context.Background(), no)
		}

		reconciler := &ProxyGroupReconciler{
			tsNamespace:       tsNamespace,
			proxyImage:        testProxyImage,
			defaultTags:       []string{"tag:test-tag"},
			tsFirewallMode:    "auto",
			defaultProxyClass: "default-pc",

			Client:   fc,
			tsClient: tsClient,
			recorder: fr,
			l:        zl.Sugar(),
			clock:    cl,
		}

		if tt.expectErrOnReconcile {
			expectError(t, reconciler, "", pg.Name)
		} else {
			expectReconciled(t, reconciler, "", pg.Name)
			if tt.name == "InvalidPort" {
				expectEvents(t, fr, []string{})
			}

			svcs := []corev1.Service{}
			if tt.expectStaticEndpoints {
				for i := range *tt.replicas {
					svc := &corev1.Service{}
					err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: fmt.Sprintf("%s-%d", pg.Name, i)}, svc)
					if err != nil {
						t.Logf("TestCase-%s: %s", tt.name, err.Error())
					}

					// NOTE: simulating kube-proxy setting NodePort
					if tt.listenerConfig.NodePortConfig == nil || len(tt.listenerConfig.NodePortConfig.PortRanges) == 0 {
						svc.Spec.Ports = []corev1.ServicePort{
							{
								Name:       directConnPortName,
								Port:       int32(directConnProxyPort),
								Protocol:   corev1.ProtocolUDP,
								NodePort:   int32(3000 + i),
								TargetPort: intstr.FromInt(directConnProxyPort),
							},
						}

						expectedPorts = append(expectedPorts, string(3000+i))

						err := fc.Update(context.Background(), svc)
						if err != nil {
							t.Fatalf("TestCase-%s: %s", tt.name, err.Error())
						}

						expectReconciled(t, reconciler, "", pg.Name)
					}
				}
			}

			if !tt.expectStaticEndpoints && len(svcs) > 0 {
				t.Fatalf("TestCase-%s: expected 0 static endpoint services, found %d", tt.name, len(svcs))
			}

			sts := &appsv1.StatefulSet{}
			if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
				t.Fatalf("TestCase-%s: failed to get StatefulSet: %v", tt.name, err)
			}

			found := false
			for _, c := range sts.Spec.Template.Spec.Containers {
				if c.Name == "tailscale" {
					for _, e := range c.Env {
						if e.Name == "PORT" {
							found = true
							break
						}
					}
				}
			}

			if !tt.expectStaticEndpoints && found {
				t.Fatalf("TestCase-%s: found unexpected 'PORT' env var on ProxyGroup StatefulSet", tt.name)
			}
			if tt.expectStaticEndpoints && !found {
				t.Fatalf("TestCase-%s: couldn't find expected 'PORT' env var on ProxyGroup StatefulSet", tt.name)
			}

			for i := range *tt.replicas {
				sec := &corev1.Secret{}
				if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: fmt.Sprintf("%s-%d-config", pg.Name, i)}, sec); err != nil {
					t.Fatalf("TestCase-%s: failed to get state Secret: %v", tt.name, err)
				}

				config := &ipn.ConfigVAlpha{}
				found = false
				for _, d := range sec.Data {
					if err := json.Unmarshal(d, config); err == nil {
						if !tt.expectStaticEndpoints && len(config.StaticEndpoints) > 0 {
							t.Fatalf("TestCase-%s: found unexpected StaticEndpoints in config Secret: %s", tt.name, config.StaticEndpoints)
						}

						if tt.expectStaticEndpoints && len(config.StaticEndpoints) < 1 {
							t.Fatalf("TestCase-%s: expected StaticEndpoints in config Secret but none found", tt.name)
						}

						for _, e := range config.StaticEndpoints {
							if !slices.Contains(expectedIPs, e.Addr().String()) && !slices.Contains(expectedPorts, strconv.FormatInt(int64(e.Port()), 10)) {
								t.Fatalf("TestCase-%s: found unexpected static endpoint %q: does not match expected IPs %q and expected Ports %q", tt.name, e.String(), expectedIPs, expectedPorts)
							}
						}
					}
				}
			}
		}

		t.Run("delete_and_cleanup", func(t *testing.T) {
			if err := fc.Delete(context.Background(), pg); err != nil {
				t.Fatalf("TestCase-%s: %s", tt.name, err.Error())
			}

			expectReconciled(t, reconciler, "", pg.Name)

			expectMissing[tsapi.ProxyGroup](t, fc, "", pg.Name)
			if expected := 0; reconciler.egressProxyGroups.Len() != expected {
				t.Fatalf("TestCase-%s: expected %d ProxyGroups, got %d", tt.name, expected, reconciler.egressProxyGroups.Len())
			}

			for _, n := range tt.nodes {
				node := &corev1.Node{
					ObjectMeta: metav1.ObjectMeta{
						Name: n.name,
					},
				}
				if err := fc.Delete(context.Background(), node); err != nil {
					t.Fatalf("TestCase-%s: %s", tt.name, err.Error())
				}
			}
			// The fake client does not clean up objects whose owner has been
			// deleted, so we can't test for the owned resources getting deleted.
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
		proxyImage:        testProxyImage,
		defaultTags:       []string{"tag:test-tag"},
		tsFirewallMode:    "auto",
		defaultProxyClass: "default-pc",

		Client:   fc,
		tsClient: tsClient,
		recorder: fr,
		l:        zl.Sugar(),
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

		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "the ProxyGroup's ProxyClass default-pc is not yet in a ready state, waiting...", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, false, "", pc)
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
		if err := fc.Status().Update(context.Background(), pc); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)

		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "0/2 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, "", pc)
		if expected := 1; reconciler.egressProxyGroups.Len() != expected {
			t.Fatalf("expected %d egress ProxyGroups, got %d", expected, reconciler.egressProxyGroups.Len())
		}
		expectProxyGroupResources(t, fc, pg, true, "", pc)
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
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady, 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, initialCfgHash, pc)
	})

	t.Run("scale_up_to_3", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](3)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionFalse, reasonProxyGroupCreating, "2/3 ProxyGroup pods running", 0, cl, zl.Sugar())
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, initialCfgHash, pc)

		addNodeIDToStateSecrets(t, fc, pg)
		expectReconciled(t, reconciler, "", pg.Name)
		tsoperator.SetProxyGroupCondition(pg, tsapi.ProxyGroupReady, metav1.ConditionTrue, reasonProxyGroupReady, reasonProxyGroupReady, 0, cl, zl.Sugar())
		pg.Status.Devices = append(pg.Status.Devices, tsapi.TailnetDevice{
			Hostname:   "hostname-nodeid-2",
			TailnetIPs: []string{"1.2.3.4", "::1"},
		})
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, initialCfgHash, pc)
	})

	t.Run("scale_down_to_1", func(t *testing.T) {
		pg.Spec.Replicas = ptr.To[int32](1)
		mustUpdate(t, fc, "", pg.Name, func(p *tsapi.ProxyGroup) {
			p.Spec = pg.Spec
		})

		expectReconciled(t, reconciler, "", pg.Name)

		pg.Status.Devices = pg.Status.Devices[:1] // truncate to only the first device.
		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, initialCfgHash, pc)
	})

	t.Run("trigger_config_change_and_observe_new_config_hash", func(t *testing.T) {
		pc.Spec.TailscaleConfig = &tsapi.TailscaleConfig{
			AcceptRoutes: true,
		}
		mustUpdate(t, fc, "", pc.Name, func(p *tsapi.ProxyClass) {
			p.Spec = pc.Spec
		})

		expectReconciled(t, reconciler, "", pg.Name)

		expectEqual(t, fc, pg)
		expectProxyGroupResources(t, fc, pg, true, "518a86e9fae64f270f8e0ec2a2ea6ca06c10f725035d3d6caca132cd61e42a74", pc)
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
		if err := fc.Delete(context.Background(), pg); err != nil {
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
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc).
		WithStatusSubresource(pc).
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
		tsNamespace: tsNamespace,
		proxyImage:  testProxyImage,
		Client:      fc,
		l:           zl.Sugar(),
		tsClient:    &fakeTSClient{},
		clock:       tstest.NewClock(tstest.ClockOpts{}),
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
		verifyProxyGroupCounts(t, reconciler, 0, 1)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
			t.Fatalf("failed to get StatefulSet: %v", err)
		}
		verifyEnvVar(t, sts, "TS_INTERNAL_APP", kubetypes.AppProxyGroupEgress)
		verifyEnvVar(t, sts, "TS_EGRESS_PROXIES_CONFIG_PATH", "/etc/proxies")
		verifyEnvVar(t, sts, "TS_ENABLE_HEALTH_CHECK", "true")

		// Verify that egress configuration has been set up.
		cm := &corev1.ConfigMap{}
		cmName := fmt.Sprintf("%s-egress-config", pg.Name)
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: cmName}, cm); err != nil {
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
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
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
		if err := fc.Create(context.Background(), pg); err != nil {
			t.Fatal(err)
		}

		expectReconciled(t, reconciler, "", pg.Name)
		verifyProxyGroupCounts(t, reconciler, 1, 2)

		sts := &appsv1.StatefulSet{}
		if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
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
}

func TestIngressAdvertiseServicesConfigPreserved(t *testing.T) {
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		Build()
	reconciler := &ProxyGroupReconciler{
		tsNamespace: tsNamespace,
		proxyImage:  testProxyImage,
		Client:      fc,
		l:           zap.Must(zap.NewDevelopment()).Sugar(),
		tsClient:    &fakeTSClient{},
		clock:       tstest.NewClock(tstest.ClockOpts{}),
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
			tsoperator.TailscaledConfigFileName(106): existingConfigBytes,
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
			tsoperator.TailscaledConfigFileName(106): expectedConfigBytes,
		},
	})
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
	if err := fc.Get(context.Background(), client.ObjectKey{Name: name}, pc); err != nil {
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
	if err := fc.Status().Update(context.Background(), pc); err != nil {
		t.Fatal(err)
	}
	return pc
}

func verifyProxyGroupCounts(t *testing.T, r *ProxyGroupReconciler, wantIngress, wantEgress int) {
	t.Helper()
	if r.ingressProxyGroups.Len() != wantIngress {
		t.Errorf("expected %d ingress proxy groups, got %d", wantIngress, r.ingressProxyGroups.Len())
	}
	if r.egressProxyGroups.Len() != wantEgress {
		t.Errorf("expected %d egress proxy groups, got %d", wantEgress, r.egressProxyGroups.Len())
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

func expectProxyGroupResources(t *testing.T, fc client.WithWatch, pg *tsapi.ProxyGroup, shouldExist bool, cfgHash string, proxyClass *tsapi.ProxyClass) {
	t.Helper()

	role := pgRole(pg, tsNamespace)
	roleBinding := pgRoleBinding(pg, tsNamespace)
	serviceAccount := pgServiceAccount(pg, tsNamespace)
	statefulSet, err := pgStatefulSet(pg, tsNamespace, testProxyImage, "auto", proxyClass)
	if err != nil {
		t.Fatal(err)
	}
	statefulSet.Annotations = defaultProxyClassAnnotations
	if cfgHash != "" {
		mak.Set(&statefulSet.Spec.Template.Annotations, podAnnotationLastSetConfigFileHash, cfgHash)
	}

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
	if err := fc.List(context.Background(), secrets); err != nil {
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

		mustUpdate(t, fc, tsNamespace, fmt.Sprintf("test-%d", i), func(s *corev1.Secret) {
			s.Data = map[string][]byte{
				currentProfileKey: []byte(key),
				key:               bytes,
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
	sharedTestCases := testCasesForLEStagingTests(pcLEStaging, pcLEStagingFalse, pcOther)
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

			// Pre-populate the fake client with ProxyClasses.
			builder = builder.WithObjects(pcLEStaging, pcLEStagingFalse, pcOther).
				WithStatusSubresource(pcLEStaging, pcLEStagingFalse, pcOther)

			fc := builder.Build()

			// If the test case needs a ProxyClass to exist, ensure it is set to Ready.
			if tt.proxyClassPerResource != "" || tt.defaultProxyClass != "" {
				name := tt.proxyClassPerResource
				if name == "" {
					name = tt.defaultProxyClass
				}
				setProxyClassReady(t, fc, cl, name)
			}

			// Create ProxyGroup
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
			mustCreate(t, fc, pg)

			reconciler := &ProxyGroupReconciler{
				tsNamespace:       tsNamespace,
				proxyImage:        testProxyImage,
				defaultTags:       []string{"tag:test"},
				defaultProxyClass: tt.defaultProxyClass,
				Client:            fc,
				tsClient:          &fakeTSClient{},
				l:                 zl.Sugar(),
				clock:             cl,
			}

			expectReconciled(t, reconciler, "", pg.Name)

			// Verify that the StatefulSet created for ProxyGrup has
			// the expected setting for the staging endpoint.
			sts := &appsv1.StatefulSet{}
			if err := fc.Get(context.Background(), client.ObjectKey{Namespace: tsNamespace, Name: pg.Name}, sts); err != nil {
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
func testCasesForLEStagingTests(pcLEStaging, pcLEStagingFalse, pcOther *tsapi.ProxyClass) []leStagingTestCase {
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
