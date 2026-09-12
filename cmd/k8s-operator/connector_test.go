// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"tailscale.com/ipn"
	tsoperator "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/k8s-operator/tsclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/util/mak"
)

func TestConnector(t *testing.T) {
	// Create a Connector that defines a Tailscale node that advertises
	// 10.40.0.0/14 route and acts as an exit node.
	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  types.UID("1234-UID"),
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       tsapi.ConnectorKind,
			APIVersion: "tailscale.com/v1alpha1",
		},
		Spec: tsapi.ConnectorSpec{
			Replicas: new(int32(1)),
			SubnetRouter: &tsapi.SubnetRouter{
				AdvertiseRoutes: []tsapi.Route{"10.40.0.0/14"},
			},
			ExitNode: true,
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(cn).
		WithStatusSubresource(cn).
		Build()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	cl := tstest.NewClock(tstest.ClockOpts{})
	cr := &ConnectorReconciler{
		Client:   fc,
		recorder: record.NewFakeRecorder(10),
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			clients:           tsclient.NewProvider(ft),
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		clock:  cl,
		logger: zl.Sugar(),
	}

	expectReconciled(t, cr, "", "test")
	fullName, shortName := findGenName(t, fc, "", "test", "connector")

	opts := configOpts{
		stsName:      shortName,
		secretName:   fullName,
		parentType:   "connector",
		hostname:     "test-connector",
		isExitNode:   true,
		subnetRoutes: "10.40.0.0/14",
		app:          kubetypes.AppConnector,
		replicas:     cn.Spec.Replicas,
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Connector status should get updated with the IP/hostname info when available.
	const hostname = "foo.tailnetxyz.ts.net"
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "device_fqdn", []byte(hostname))
		mak.Set(&secret.Data, "device_ips", []byte(`["127.0.0.1", "::1"]`))
	})
	expectReconciled(t, cr, "", "test")
	cn.Finalizers = append(cn.Finalizers, "tailscale.com/finalizer")
	cn.Status.IsExitNode = cn.Spec.ExitNode
	cn.Status.SubnetRoutes = cn.Spec.SubnetRouter.AdvertiseRoutes.Stringify()
	cn.Status.Hostname = hostname
	cn.Status.Devices = []tsapi.ConnectorDevice{{
		Hostname:   hostname,
		TailnetIPs: []string{"127.0.0.1", "::1"},
	}}
	cn.Status.TailnetIPs = []string{"127.0.0.1", "::1"}
	expectEqual(t, fc, cn, func(o *tsapi.Connector) {
		o.Status.Conditions = nil
	})

	// Add another route to be advertised.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.AdvertiseRoutes = []tsapi.Route{"10.40.0.0/14", "10.44.0.0/20"}
	})
	opts.subnetRoutes = "10.40.0.0/14,10.44.0.0/20"
	expectReconciled(t, cr, "", "test")

	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Remove a route.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.AdvertiseRoutes = []tsapi.Route{"10.44.0.0/20"}
	})
	opts.subnetRoutes = "10.44.0.0/20"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Remove the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = nil
	})
	opts.subnetRoutes = ""
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Re-add the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = &tsapi.SubnetRouter{
			AdvertiseRoutes: []tsapi.Route{"10.44.0.0/20"},
		}
	})
	opts.subnetRoutes = "10.44.0.0/20"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Set an invalid 4via6 route (site ID too large).
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.AdvertiseRoutes = []tsapi.Route{"fd7a:115c:a1e0:b1a:1:0:a2c:0/116"}
	})
	expectReconciled(t, cr, "", "test")
	// STS should still have the previous valid route, unchanged.
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Set a valid 4via6 route.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.AdvertiseRoutes = []tsapi.Route{"fd7a:115c:a1e0:b1a:0:1:a2c:0/116"}
	})
	opts.subnetRoutes = "fd7a:115c:a1e0:b1a:0:1:a2c:0/116"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Delete the Connector.
	if err = fc.Delete(context.Background(), cn); err != nil {
		t.Fatalf("error deleting Connector: %v", err)
	}

	expectRequeue(t, cr, "", "test")
	expectReconciled(t, cr, "", "test")

	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)

	// Create a Connector that advertises a route and is not an exit node.
	cn = &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  types.UID("1234-UID"),
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       tsapi.ConnectorKind,
			APIVersion: "tailscale.io/v1alpha1",
		},
		Spec: tsapi.ConnectorSpec{
			Replicas: new(int32(1)),
			SubnetRouter: &tsapi.SubnetRouter{
				AdvertiseRoutes: []tsapi.Route{"10.40.0.0/14"},
			},
		},
	}
	opts.subnetRoutes = "10.44.0.0/14"
	opts.isExitNode = false
	mustCreate(t, fc, cn)
	expectReconciled(t, cr, "", "test")
	fullName, shortName = findGenName(t, fc, "", "test", "connector")

	opts = configOpts{
		stsName:      shortName,
		secretName:   fullName,
		parentType:   "connector",
		subnetRoutes: "10.40.0.0/14",
		hostname:     "test-connector",
		app:          kubetypes.AppConnector,
		replicas:     cn.Spec.Replicas,
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Add an exit node.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.ExitNode = true
	})
	opts.isExitNode = true
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// Delete the Connector.
	if err = fc.Delete(context.Background(), cn); err != nil {
		t.Fatalf("error deleting Connector: %v", err)
	}

	expectRequeue(t, cr, "", "test")
	expectReconciled(t, cr, "", "test")

	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
}

func TestConnectorWithProxyClass(t *testing.T) {
	// Setup
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-metadata"},
		Spec: tsapi.ProxyClassSpec{StatefulSet: &tsapi.StatefulSet{
			Labels:      tsapi.Labels{"foo": "bar"},
			Annotations: map[string]string{"bar.io/foo": "some-val"},
			Pod:         &tsapi.Pod{Annotations: map[string]string{"foo.io/bar": "some-val"}}}},
	}
	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  types.UID("1234-UID"),
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       tsapi.ConnectorKind,
			APIVersion: "tailscale.io/v1alpha1",
		},
		Spec: tsapi.ConnectorSpec{
			Replicas: new(int32(1)),
			SubnetRouter: &tsapi.SubnetRouter{
				AdvertiseRoutes: []tsapi.Route{"10.40.0.0/14"},
			},

			ExitNode: true,
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, cn).
		WithStatusSubresource(pc, cn).
		Build()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	cr := &ConnectorReconciler{
		Client: fc,
		clock:  cl,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			clients:           tsclient.NewProvider(ft),
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
	}

	// 1. Connector is created with no ProxyClass specified, create
	// resources with the default configuration.
	expectReconciled(t, cr, "", "test")
	fullName, shortName := findGenName(t, fc, "", "test", "connector")

	opts := configOpts{
		stsName:      shortName,
		secretName:   fullName,
		parentType:   "connector",
		hostname:     "test-connector",
		isExitNode:   true,
		subnetRoutes: "10.40.0.0/14",
		app:          kubetypes.AppConnector,
		replicas:     cn.Spec.Replicas,
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// 2. Update Connector to specify a ProxyClass. ProxyClass is not yet
	// ready, so its configuration is NOT applied to the Connector
	// resources.
	mustUpdate(t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.ProxyClass = "custom-metadata"
	})
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// 3. ProxyClass is set to Ready by proxy-class reconciler. Connector
	// get reconciled and configuration from the ProxyClass is applied to
	// its resources.
	mustUpdateStatus(t, fc, "", "custom-metadata", func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: pc.Generation,
			}}}
	})
	opts.proxyClass = pc.Name
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)

	// 4. Connector.spec.proxyClass field is unset, Connector gets
	// reconciled and configuration from the ProxyClass is removed from the
	// cluster resources for the Connector.
	mustUpdate(t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.ProxyClass = ""
	})
	opts.proxyClass = ""
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)
}

func TestConnectorWithAppConnector(t *testing.T) {
	// Setup
	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  types.UID("1234-UID"),
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       tsapi.ConnectorKind,
			APIVersion: "tailscale.io/v1alpha1",
		},
		Spec: tsapi.ConnectorSpec{
			Replicas:     new(int32(1)),
			AppConnector: &tsapi.AppConnector{},
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(cn).
		WithStatusSubresource(cn).
		Build()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	fr := record.NewFakeRecorder(1)
	cr := &ConnectorReconciler{
		Client: fc,
		clock:  cl,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			clients:           tsclient.NewProvider(ft),
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger:   zl.Sugar(),
		recorder: fr,
	}

	// 1. Connector with app connector is created and becomes ready
	expectReconciled(t, cr, "", "test")
	fullName, shortName := findGenName(t, fc, "", "test", "connector")
	opts := configOpts{
		stsName:        shortName,
		secretName:     fullName,
		parentType:     "connector",
		hostname:       "test-connector",
		app:            kubetypes.AppConnector,
		isAppConnector: true,
		replicas:       cn.Spec.Replicas,
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts))
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeResourceReqs)
	// Connector's ready condition should be set to true

	cn.ObjectMeta.Finalizers = append(cn.ObjectMeta.Finalizers, "tailscale.com/finalizer")
	cn.Status.IsAppConnector = true
	cn.Status.Devices = []tsapi.ConnectorDevice{}
	cn.Status.Conditions = []metav1.Condition{{
		Type:               string(tsapi.ConnectorReady),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
		Reason:             reasonConnectorCreated,
		Message:            reasonConnectorCreated,
	}}
	expectEqual(t, fc, cn)

	// 2. Connector with invalid app connector routes has status set to invalid
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.AppConnector.Routes = tsapi.Routes{"1.2.3.4/5"}
	})
	cn.Spec.AppConnector.Routes = tsapi.Routes{"1.2.3.4/5"}
	expectReconciled(t, cr, "", "test")
	cn.Status.Conditions = []metav1.Condition{{
		Type:               string(tsapi.ConnectorReady),
		Status:             metav1.ConditionFalse,
		LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
		Reason:             reasonConnectorInvalid,
		Message:            "Connector is invalid: route 1.2.3.4/5 has non-address bits set; expected 0.0.0.0/5",
	}}
	expectEqual(t, fc, cn)

	// 3. Connector with valid app connnector routes becomes ready
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.AppConnector.Routes = tsapi.Routes{"10.88.2.21/32"}
	})
	cn.Spec.AppConnector.Routes = tsapi.Routes{"10.88.2.21/32"}
	cn.Status.Conditions = []metav1.Condition{{
		Type:               string(tsapi.ConnectorReady),
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Time{Time: cl.Now().Truncate(time.Second)},
		Reason:             reasonConnectorCreated,
		Message:            reasonConnectorCreated,
	}}
	expectReconciled(t, cr, "", "test")
}

func TestConnectorWithMultipleReplicas(t *testing.T) {
	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  types.UID("1234-UID"),
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       tsapi.ConnectorKind,
			APIVersion: "tailscale.io/v1alpha1",
		},
		Spec: tsapi.ConnectorSpec{
			Replicas:       new(int32(3)),
			AppConnector:   &tsapi.AppConnector{},
			HostnamePrefix: "test-connector",
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(cn).
		WithStatusSubresource(cn).
		Build()
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	fr := record.NewFakeRecorder(1)
	cr := &ConnectorReconciler{
		Client: fc,
		clock:  cl,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			clients:           tsclient.NewProvider(ft),
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger:   zl.Sugar(),
		recorder: fr,
	}

	// 1. Ensure that our connector resource is reconciled.
	expectReconciled(t, cr, "", "test")

	// 2. Ensure we have a number of secrets matching the number of replicas.
	names := findGenNames(t, fc, "", "test", "connector")
	if int32(len(names)) != *cn.Spec.Replicas {
		t.Fatalf("expected %d secrets, got %d", *cn.Spec.Replicas, len(names))
	}

	// 3. Ensure each device has the correct hostname prefix and ordinal suffix.
	for i, name := range names {
		expected := expectedSecret(t, fc, configOpts{
			secretName:     name,
			hostname:       string(cn.Spec.HostnamePrefix) + "-" + strconv.Itoa(i),
			isAppConnector: true,
			parentType:     "connector",
			namespace:      cr.tsnamespace,
		})

		expectEqual(t, fc, expected)
	}

	// 4. Ensure the generated stateful set has the matching number of replicas
	shortName := strings.TrimSuffix(names[0], "-0")

	var sts appsv1.StatefulSet
	if err = fc.Get(t.Context(), types.NamespacedName{Namespace: "operator-ns", Name: shortName}, &sts); err != nil {
		t.Fatalf("failed to get StatefulSet %q: %v", shortName, err)
	}

	if sts.Spec.Replicas == nil {
		t.Fatalf("actual StatefulSet %q does not have replicas set", shortName)
	}

	if *sts.Spec.Replicas != *cn.Spec.Replicas {
		t.Fatalf("expected %d replicas, got %d", *cn.Spec.Replicas, *sts.Spec.Replicas)
	}

	// 5. We'll scale the connector down by 1 replica and make sure its secret is cleaned up
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.Replicas = new(int32(2))
	})
	expectReconciled(t, cr, "", "test")
	names = findGenNames(t, fc, "", "test", "connector")
	if len(names) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(names))
	}
}

func TestConnectorWithStaticEndpoints(t *testing.T) {
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: "static-endpoints"},
		Spec: tsapi.ProxyClassSpec{
			StaticEndpoints: &tsapi.StaticEndpointsConfig{
				NodePort: &tsapi.NodePortConfig{
					Ports:    []tsapi.PortRange{{Port: 30001, EndPort: 30003}},
					Selector: map[string]string{"zone": "eu"},
				},
			},
		},
	}
	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
			UID:  types.UID("1234-UID"),
		},
		TypeMeta: metav1.TypeMeta{
			Kind:       tsapi.ConnectorKind,
			APIVersion: "tailscale.com/v1alpha1",
		},
		Spec: tsapi.ConnectorSpec{
			Replicas:       new(int32(2)),
			HostnamePrefix: "test-connector",
			ExitNode:       true,
			ProxyClass:     pc.Name,
		},
	}
	nodes := []*corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a", Labels: map[string]string{"zone": "eu"}},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeExternalIP, Address: "152.88.10.11"},
			}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-b", Labels: map[string]string{"zone": "eu"}},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "152.88.10.12"},
			}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-c", Labels: map[string]string{"zone": "us"}},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "152.88.10.13"},
			}},
		},
	}
	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pc, cn, nodes[0], nodes[1], nodes[2]).
		WithStatusSubresource(pc, cn).
		Build()
	mustUpdateStatus(t, fc, "", pc.Name, func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassReady),
				ObservedGeneration: pc.Generation,
			}}}
	})
	ft := &fakeTSClient{}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	fr := record.NewFakeRecorder(10)
	cr := &ConnectorReconciler{
		Client: fc,
		clock:  cl,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			clients:           tsclient.NewProvider(ft),
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger:   zl.Sugar(),
		recorder: fr,
	}

	// 1. A NodePort Service gets created for each replica, targeting a
	// shared tailscaled port, with a NodePort from the ProxyClass's
	// configured ranges and a selector matching only that replica's Pod.
	expectReconciled(t, cr, "", "test")
	names := findGenNames(t, fc, "", "test", "connector")
	if int32(len(names)) != *cn.Spec.Replicas {
		t.Fatalf("expected %d secrets, got %d", *cn.Spec.Replicas, len(names))
	}
	shortName := strings.TrimSuffix(names[0], "-0")

	var tailscaledPort int32
	nodePorts := make(map[int32]int32) // replica ordinal -> NodePort
	for i := range *cn.Spec.Replicas {
		svc := &corev1.Service{}
		svcName := fmt.Sprintf("test-%d-nodeport", i)
		if err := fc.Get(t.Context(), types.NamespacedName{Namespace: "operator-ns", Name: svcName}, svc); err != nil {
			t.Fatalf("failed to get NodePort Service %q: %v", svcName, err)
		}
		if svc.Spec.Type != corev1.ServiceTypeNodePort {
			t.Errorf("expected Service %q to be of type NodePort, got %q", svcName, svc.Spec.Type)
		}
		if len(svc.Spec.Ports) != 1 {
			t.Fatalf("expected Service %q to have 1 port, got %d", svcName, len(svc.Spec.Ports))
		}
		port := svc.Spec.Ports[0]
		if port.Protocol != corev1.ProtocolUDP {
			t.Errorf("expected Service %q port to be UDP, got %q", svcName, port.Protocol)
		}
		if port.NodePort < 30001 || port.NodePort > 30003 {
			t.Errorf("expected Service %q NodePort to be in range [30001, 30003], got %d", svcName, port.NodePort)
		}
		nodePorts[i] = port.NodePort
		if tailscaledPort == 0 {
			tailscaledPort = port.Port
		} else if port.Port != tailscaledPort {
			t.Errorf("expected all NodePort Services to share target port %d, but Service %q has %d", tailscaledPort, svcName, port.Port)
		}
		wantSelector := map[string]string{appsv1.StatefulSetPodNameLabel: fmt.Sprintf("%s-%d", shortName, i)}
		if !reflect.DeepEqual(svc.Spec.Selector, wantSelector) {
			t.Errorf("expected Service %q selector to be %v, got %v", svcName, wantSelector, svc.Spec.Selector)
		}
	}
	if nodePorts[0] == nodePorts[1] {
		t.Errorf("expected replicas to get distinct NodePorts, both got %d", nodePorts[0])
	}

	// 2. Each replica's tailscaled config gets the Node ExternalIPs of the
	// selected Nodes combined with its NodePort as static endpoints.
	endpointsForReplica := func(i int32) []netip.AddrPort {
		return []netip.AddrPort{
			netip.AddrPortFrom(netip.MustParseAddr("152.88.10.11"), uint16(nodePorts[i])),
			netip.AddrPortFrom(netip.MustParseAddr("152.88.10.12"), uint16(nodePorts[i])),
		}
	}
	staticEndpointsFromSecret := func(name string, capver tailcfg.CapabilityVersion) []netip.AddrPort {
		t.Helper()
		sec := &corev1.Secret{}
		if err := fc.Get(t.Context(), types.NamespacedName{Namespace: "operator-ns", Name: name}, sec); err != nil {
			t.Fatalf("failed to get config Secret %q: %v", name, err)
		}
		// The fake client stores StringData as written rather than
		// converting it to Data like the real API server would.
		confB, ok := sec.StringData[tsoperator.TailscaledConfigFileName(capver)]
		if !ok {
			t.Fatalf("config Secret %q does not contain a capver %d config, keys: %v", name, capver, slices.Collect(maps.Keys(sec.StringData)))
		}
		conf := &ipn.ConfigVAlpha{}
		if err := json.Unmarshal([]byte(confB), conf); err != nil {
			t.Fatalf("failed to unmarshal config from Secret %q: %v", name, err)
		}
		return conf.StaticEndpoints
	}
	for i, name := range names {
		want := endpointsForReplica(int32(i))
		if got := staticEndpointsFromSecret(name, 107); !reflect.DeepEqual(got, want) {
			t.Errorf("expected replica %d static endpoints %v, got %v", i, want, got)
		}
	}

	// 3. tailscaled listens on the target port of the NodePort Services.
	sts := &appsv1.StatefulSet{}
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: "operator-ns", Name: shortName}, sts); err != nil {
		t.Fatalf("failed to get StatefulSet %q: %v", shortName, err)
	}
	findPortEnv := func(sts *appsv1.StatefulSet) *corev1.EnvVar {
		for _, env := range sts.Spec.Template.Spec.Containers[0].Env {
			if env.Name == "PORT" {
				return &env
			}
		}
		return nil
	}
	if env := findPortEnv(sts); env == nil || env.Value != strconv.Itoa(int(tailscaledPort)) {
		t.Errorf("expected StatefulSet %q to have PORT env %d, got %v", shortName, tailscaledPort, env)
	}

	// 4. Reconciling again does not change the endpoints or their order.
	expectReconciled(t, cr, "", "test")
	for i, name := range names {
		if got := staticEndpointsFromSecret(name, 107); !reflect.DeepEqual(got, endpointsForReplica(int32(i))) {
			t.Errorf("static endpoints for replica %d changed across reconciles: %v", i, got)
		}
	}

	// 5. The Connector's device statuses report the static endpoints.
	for i, name := range names {
		mustUpdate(t, fc, "operator-ns", name, func(secret *corev1.Secret) {
			mak.Set(&secret.Data, "device_id", []byte(fmt.Sprintf("1234-%d", i)))
			mak.Set(&secret.Data, "device_fqdn", []byte(fmt.Sprintf("test-connector-%d.tailnetxyz.ts.net", i)))
			mak.Set(&secret.Data, "device_ips", []byte(`["127.0.0.1"]`))
		})
	}
	expectReconciled(t, cr, "", "test")
	if err := fc.Get(t.Context(), types.NamespacedName{Name: "test"}, cn); err != nil {
		t.Fatalf("failed to get Connector: %v", err)
	}
	if len(cn.Status.Devices) != 2 {
		t.Fatalf("expected 2 devices in Connector status, got %d", len(cn.Status.Devices))
	}
	for i, dev := range cn.Status.Devices {
		want := make([]string, 0, 2)
		for _, ep := range endpointsForReplica(int32(i)) {
			want = append(want, ep.String())
		}
		if !reflect.DeepEqual(dev.StaticEndpoints, want) {
			t.Errorf("expected device %d status static endpoints %v, got %v", i, want, dev.StaticEndpoints)
		}
	}

	// 6. Scaling down deletes the excess NodePort Services and keeps the
	// remaining replica's allocated NodePort.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.Replicas = new(int32(1))
	})
	expectReconciled(t, cr, "", "test")
	expectMissing[corev1.Service](t, fc, "operator-ns", "test-1-nodeport")
	svc := &corev1.Service{}
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: "operator-ns", Name: "test-0-nodeport"}, svc); err != nil {
		t.Fatalf("failed to get NodePort Service after scale down: %v", err)
	}
	if svc.Spec.Ports[0].NodePort != nodePorts[0] {
		t.Errorf("expected replica 0 to keep NodePort %d after scale down, got %d", nodePorts[0], svc.Spec.Ports[0].NodePort)
	}

	// 7. If there are not enough free ports in the configured ranges for
	// all replicas, provisioning fails with an event and the Connector is
	// not ready.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.Replicas = new(int32(4))
	})
	expectError(t, cr, "", "test")
	expectEvents(t, fr, []string{"Warning ConnectorCreationFailed Failed creating Connector: failed to reconcile static endpoints: error provisioning NodePort Services for static endpoints: failed to allocate NodePorts to Connector Services: not enough available ports to allocate all replicas (needed 4, got 3). Field 'spec.staticEndpoints.nodePort.ports' on ProxyClass \"static-endpoints\" must have bigger range allocated"})
	if err := fc.Get(t.Context(), types.NamespacedName{Name: "test"}, cn); err != nil {
		t.Fatalf("failed to get Connector: %v", err)
	}
	readyIdx := slices.IndexFunc(cn.Status.Conditions, func(cond metav1.Condition) bool {
		return cond.Type == string(tsapi.ConnectorReady)
	})
	if readyIdx == -1 || cn.Status.Conditions[readyIdx].Status != metav1.ConditionFalse {
		t.Errorf("expected ConnectorReady condition to be False after port allocation failure, got %+v", cn.Status.Conditions)
	}

	// 8. Removing static endpoints from the ProxyClass deletes the
	// NodePort Services and removes the static endpoints from the
	// tailscaled configs, but keeps the headless Service.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.Replicas = new(int32(1))
	})
	mustUpdate[tsapi.ProxyClass](t, fc, "", pc.Name, func(pc *tsapi.ProxyClass) {
		pc.Spec.StaticEndpoints = nil
	})
	mustUpdateStatus(t, fc, "", pc.Name, func(pc *tsapi.ProxyClass) {
		pc.Status.Conditions[0].ObservedGeneration = pc.Generation
	})
	expectReconciled(t, cr, "", "test")
	expectMissing[corev1.Service](t, fc, "operator-ns", "test-0-nodeport")
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: "operator-ns", Name: shortName}, &corev1.Service{}); err != nil {
		t.Fatalf("expected headless Service %q to still exist: %v", shortName, err)
	}
	if eps := staticEndpointsFromSecret(names[0], 107); eps != nil {
		t.Errorf("expected no static endpoints in config after removal, got %v", eps)
	}
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: "operator-ns", Name: shortName}, sts); err != nil {
		t.Fatalf("failed to get StatefulSet %q: %v", shortName, err)
	}
	if env := findPortEnv(sts); env != nil {
		t.Errorf("expected StatefulSet %q to no longer have a PORT env, got %v", shortName, env)
	}
}
