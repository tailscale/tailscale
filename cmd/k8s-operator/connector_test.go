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
	"tailscale.com/tstest"
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
		stsName:                    shortName,
		secretName:                 fullName,
		parentType:                 "connector",
		hostname:                   "test-connector",
		shouldUseDeclarativeConfig: true,
		isExitNode:                 true,
		subnetRoutes:               "10.40.0.0/14",
		confFileHash:               "9321660203effb80983eaecc7b5ac5a8c53934926f46e895b9fe295dcfc5a904",
	}
	expectEqual(t, fc, expectedSecret(t, opts))
	expectEqual(t, fc, expectedSTS(opts))

	// Add another route to be advertised.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.AdvertiseRoutes = []tsapi.Route{"10.40.0.0/14", "10.44.0.0/20"}
	})
	opts.subnetRoutes = "10.40.0.0/14,10.44.0.0/20"
	opts.confFileHash = "fb6c4daf67425f983985750cd8d6f2beae77e614fcb34176604571f5623d6862"
	expectReconciled(t, cr, "", "test")

	expectEqual(t, fc, expectedSTS(opts))

	// Remove a route.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.AdvertiseRoutes = []tsapi.Route{"10.44.0.0/20"}
	})
	opts.subnetRoutes = "10.44.0.0/20"
	opts.confFileHash = "bacba177bcfe3849065cf6fee53d658a9bb4144197ac5b861727d69ea99742bb"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(opts))

	// Remove the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = nil
	})
	opts.subnetRoutes = ""
	opts.confFileHash = "7c421a99128eb80e79a285a82702f19f8f720615542a15bd794858a6275d8079"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(opts))

	// Re-add the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = &tsapi.SubnetRouter{
			AdvertiseRoutes: []tsapi.Route{"10.44.0.0/20"},
		}
	})
	opts.subnetRoutes = "10.44.0.0/20"
	opts.confFileHash = "bacba177bcfe3849065cf6fee53d658a9bb4144197ac5b861727d69ea99742bb"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(opts))

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
		stsName:                    shortName,
		secretName:                 fullName,
		parentType:                 "connector",
		shouldUseDeclarativeConfig: true,
		subnetRoutes:               "10.40.0.0/14",
		hostname:                   "test-connector",
		confFileHash:               "57d922331890c9b1c8c6ae664394cb254334c551d9cd9db14537b5d9da9fb17e",
	}
	expectEqual(t, fc, expectedSecret(t, opts))
	expectEqual(t, fc, expectedSTS(opts))

	// Add an exit node.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.ExitNode = true
	})
	opts.isExitNode = true
	opts.confFileHash = "1499b591fd97a50f0330db6ec09979792c49890cf31f5da5bb6a3f50dba1e77a"
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedSTS(opts))

	// Delete the Connector.
	if err = fc.Delete(context.Background(), cn); err != nil {
		t.Fatalf("error deleting Connector: %v", err)
	}

	expectRequeue(t, cr, "", "test")
	expectReconciled(t, cr, "", "test")

	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
}
