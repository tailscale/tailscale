// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
	"tailscale.com/types/ptr"
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
				Routes: []tsapi.Route{"10.40.0.0/14"},
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

	expectEqual(t, fc, expectedSecret(fullName, "", "connector"))
	opts := connectorSTSOpts{
		connectorName: "test",
		stsName:       shortName,
		secretName:    fullName,
		routes:        "10.40.0.0/14",
		isExitNode:    true,
	}
	expectEqual(t, fc, expectedConnectorSTS(opts))

	// Add another route to be advertised.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.Routes = []tsapi.Route{"10.40.0.0/14", "10.44.0.0/20"}
	})
	expectReconciled(t, cr, "", "test")
	opts.routes = "10.40.0.0/14,10.44.0.0/20"

	expectEqual(t, fc, expectedConnectorSTS(opts))

	// Remove a route.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.Routes = []tsapi.Route{"10.44.0.0/20"}
	})
	expectReconciled(t, cr, "", "test")
	opts.routes = "10.44.0.0/20"
	expectEqual(t, fc, expectedConnectorSTS(opts))

	// Remove the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = nil
	})
	expectReconciled(t, cr, "", "test")
	opts.routes = ""
	expectEqual(t, fc, expectedConnectorSTS(opts))

	// Re-add the subnet router.
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter = &tsapi.SubnetRouter{
			Routes: []tsapi.Route{"10.44.0.0/20"},
		}
	})
	expectReconciled(t, cr, "", "test")
	opts.routes = "10.44.0.0/20"
	expectEqual(t, fc, expectedConnectorSTS(opts))

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
				Routes: []tsapi.Route{"10.40.0.0/14"},
			},
		},
	}
	mustCreate(t, fc, cn)
	expectReconciled(t, cr, "", "test")
	fullName, shortName = findGenName(t, fc, "", "test", "connector")

	expectEqual(t, fc, expectedSecret(fullName, "", "connector"))
	opts = connectorSTSOpts{
		connectorName: "test",
		stsName:       shortName,
		secretName:    fullName,
		routes:        "10.40.0.0/14",
		isExitNode:    false,
	}
	expectEqual(t, fc, expectedConnectorSTS(opts))

	// Delete the Connector.
	if err = fc.Delete(context.Background(), cn); err != nil {
		t.Fatalf("error deleting Connector: %v", err)
	}

	expectRequeue(t, cr, "", "test")
	expectReconciled(t, cr, "", "test")

	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
}

type connectorSTSOpts struct {
	stsName       string
	secretName    string
	connectorName string
	hostname      string
	routes        string
	isExitNode    bool
}

func expectedConnectorSTS(opts connectorSTSOpts) *appsv1.StatefulSet {
	var hostname string
	if opts.hostname != "" {
		hostname = opts.hostname
	} else {
		hostname = opts.connectorName + "-connector"
	}
	containerEnv := []corev1.EnvVar{
		{Name: "TS_USERSPACE", Value: "false"},
		{Name: "TS_AUTH_ONCE", Value: "true"},
		{Name: "TS_KUBE_SECRET", Value: opts.secretName},
		{Name: "TS_HOSTNAME", Value: hostname},
		{Name: "TS_EXTRA_ARGS", Value: fmt.Sprintf("--advertise-exit-node=%v", opts.isExitNode)},
		{Name: "TS_ROUTES", Value: opts.routes},
	}
	sts := &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StatefulSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      opts.stsName,
			Namespace: "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   "",
				"tailscale.com/parent-resource-type": "connector",
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "1234-UID"},
			},
			ServiceName: opts.stsName,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					DeletionGracePeriodSeconds: ptr.To[int64](10),
					Labels:                     map[string]string{"app": "1234-UID"},
					Annotations: map[string]string{
						"tailscale.com/operator-last-set-hostname": hostname,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "proxies",
					InitContainers: []corev1.Container{
						{
							Name:    "sysctler",
							Image:   "tailscale/tailscale",
							Command: []string{"/bin/sh"},
							Args:    []string{"-c", "sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1"},
							SecurityContext: &corev1.SecurityContext{
								Privileged: ptr.To(true),
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:  "tailscale",
							Image: "tailscale/tailscale",
							Env:   containerEnv,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN"},
								},
							},
							ImagePullPolicy: "Always",
						},
					},
				},
			},
		},
	}
	return sts
}
