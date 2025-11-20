// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
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
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
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
			Replicas: ptr.To[int32](1),
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
			tsClient:          ft,
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
			Replicas: ptr.To[int32](1),
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
			Replicas: ptr.To[int32](1),
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
			tsClient:          ft,
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
			Replicas:     ptr.To[int32](1),
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
			tsClient:          ft,
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
			Replicas:       ptr.To[int32](3),
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
			tsClient:          ft,
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
		conn.Spec.Replicas = ptr.To[int32](2)
	})
	expectReconciled(t, cr, "", "test")
	names = findGenNames(t, fc, "", "test", "connector")
	if len(names) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(names))
	}
}
