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
	"tailscale.com/types/ptr"
)

func TestConnector(t *testing.T) {
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
	// Create a Connector with a subnet router definition
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
	fullName, shortName := findGenName(t, fc, "", "test", "subnetrouter")

	expectEqual(t, fc, expectedSecret(fullName, "", "subnetrouter"))
	expectEqual(t, fc, expectedConnectorSTS(shortName, fullName, "10.40.0.0/14"))

	// Add another CIDR
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.Routes = []tsapi.Route{"10.40.0.0/14", "10.44.0.0/20"}
	})
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedConnectorSTS(shortName, fullName, "10.40.0.0/14,10.44.0.0/20"))

	// Remove a CIDR
	mustUpdate[tsapi.Connector](t, fc, "", "test", func(conn *tsapi.Connector) {
		conn.Spec.SubnetRouter.Routes = []tsapi.Route{"10.44.0.0/20"}
	})
	expectReconciled(t, cr, "", "test")
	expectEqual(t, fc, expectedConnectorSTS(shortName, fullName, "10.44.0.0/20"))

	// Delete the Connector
	if err = fc.Delete(context.Background(), cn); err != nil {
		t.Fatalf("error deleting Connector: %v", err)
	}

	expectRequeue(t, cr, "", "test")
	expectReconciled(t, cr, "", "test")

	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)

}

func expectedConnectorSTS(stsName, secretName, routes string) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		TypeMeta: metav1.TypeMeta{
			Kind:       "StatefulSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      stsName,
			Namespace: "operator-ns",
			Labels: map[string]string{
				"tailscale.com/managed":              "true",
				"tailscale.com/parent-resource":      "test",
				"tailscale.com/parent-resource-ns":   "",
				"tailscale.com/parent-resource-type": "subnetrouter",
			},
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "1234-UID"},
			},
			ServiceName: stsName,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					DeletionGracePeriodSeconds: ptr.To[int64](10),
					Labels:                     map[string]string{"app": "1234-UID"},
					Annotations: map[string]string{
						"tailscale.com/operator-last-set-hostname": "test-subnetrouter",
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
							Env: []corev1.EnvVar{
								{Name: "TS_USERSPACE", Value: "false"},
								{Name: "TS_AUTH_ONCE", Value: "true"},
								{Name: "TS_KUBE_SECRET", Value: secretName},
								{Name: "TS_HOSTNAME", Value: "test-subnetrouter"},
								{Name: "TS_ROUTES", Value: routes},
							},
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
}
