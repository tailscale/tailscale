// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/kube/kubetypes"
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
		Client: fc,
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
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts), nil)
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

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

	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// Remove a route.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.AdvertiseRoutes = []tsapi.Route{"10.44.0.0/20"}
	})
	opts.subnetRoutes = "10.44.0.0/20"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// Remove the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = nil
	})
	opts.subnetRoutes = ""
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// Re-add the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = &tsapi.SubnetRouter{
			AdvertiseRoutes: []tsapi.Route{"10.44.0.0/20"},
		}
	})
	opts.subnetRoutes = "10.44.0.0/20"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

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
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts), nil)
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// Add an exit node.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.ExitNode = true
	})
	opts.isExitNode = true
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

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
			Labels:      map[string]string{"foo": "bar"},
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
	}
	expectEqual(t, fc, expectedSecret(t, fc, opts), nil)
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// 2. Update Connector to specify a ProxyClass. ProxyClass is not yet
	// ready, so its configuration is NOT applied to the Connector
	// resources.
	mustUpdate(t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.ProxyClass = "custom-metadata"
	})
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// 3. ProxyClass is set to Ready by proxy-class reconciler. Connector
	// get reconciled and configuration from the ProxyClass is applied to
	// its resources.
	mustUpdateStatus(t, fc, "", "custom-metadata", func(pc *tsapi.ProxyClass) {
		pc.Status = tsapi.ProxyClassStatus{
			Conditions: []metav1.Condition{{
				Status:             metav1.ConditionTrue,
				Type:               string(tsapi.ProxyClassready),
				ObservedGeneration: pc.Generation,
			}}}
	})
	opts.proxyClass = pc.Name
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)

	// 4. Connector.spec.proxyClass field is unset, Connector gets
	// reconciled and configuration from the ProxyClass is removed from the
	// cluster resources for the Connector.
	mustUpdate(t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.ProxyClass = ""
	})
	opts.proxyClass = ""
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(t, fc, opts), removeHashAnnotation)
}
