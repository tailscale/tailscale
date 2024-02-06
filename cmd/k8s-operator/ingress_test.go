// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"testing"

	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/ipn"
	"tailscale.com/types/ptr"
	"tailscale.com/util/mak"
)

func TestTailscaleIngress(t *testing.T) {
	tsIngressClass := &networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "tailscale"}, Spec: networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"}}
	fc := fake.NewFakeClient(tsIngressClass)
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	ingR := &IngressReconciler{
		Client: fc,
		ssr: &tailscaleSTSReconciler{
			Client:            fc,
			tsClient:          ft,
			tsnetServer:       fakeTsnetServer,
			defaultTags:       []string{"tag:k8s"},
			operatorNamespace: "operator-ns",
			proxyImage:        "tailscale/tailscale",
		},
		logger: zl.Sugar(),
	}

	// 1. Resources get created for regular Ingress
	ing := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
			// The apiserver is supposed to set the UID, but the fake client
			// doesn't. So, set it explicitly because other code later depends
			// on it being set.
			UID: types.UID("1234-UID"),
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "test",
					Port: networkingv1.ServiceBackendPort{
						Number: 8080,
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{Hosts: []string{"default-test"}},
			},
		},
	}
	mustCreate(t, fc, ing)
	mustCreate(t, fc, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "1.2.3.4",
			Ports: []corev1.ServicePort{{
				Port: 8080,
				Name: "http"},
			},
		},
	})

	expectReconciled(t, ingR, "default", "test")

	fullName, shortName := findGenName(t, fc, "default", "test", "ingress")
	opts := configOpts{
		stsName:    shortName,
		secretName: fullName,
		namespace:  "default",
		parentType: "ingress",
		hostname:   "default-test",
	}
	serveConfig := &ipn.ServeConfig{
		TCP: map[uint16]*ipn.TCPPortHandler{443: {HTTPS: true}},
		Web: map[ipn.HostPort]*ipn.WebServerConfig{"${TS_CERT_DOMAIN}:443": {Handlers: map[string]*ipn.HTTPHandler{"/": {Proxy: "http://1.2.3.4:8080/"}}}},
	}
	opts.serveConfig = serveConfig

	expectEqual(t, fc, expectedSecret(t, opts))
	expectEqual(t, fc, expectedHeadlessService(shortName, "ingress"))
	expectEqual(t, fc, expectedSTSUserspace(opts))

	// 2. Ingress status gets updated with ingress proxy's MagicDNS name
	// once that becomes available.
	mustUpdate(t, fc, "operator-ns", opts.secretName, func(secret *corev1.Secret) {
		mak.Set(&secret.Data, "device_id", []byte("1234"))
		mak.Set(&secret.Data, "device_fqdn", []byte("foo.tailnetxyz.ts.net"))
	})
	expectReconciled(t, ingR, "default", "test")
	ing.Finalizers = append(ing.Finalizers, "tailscale.com/finalizer")
	ing.Status.LoadBalancer = networkingv1.IngressLoadBalancerStatus{
		Ingress: []networkingv1.IngressLoadBalancerIngress{
			{Hostname: "foo.tailnetxyz.ts.net", Ports: []networkingv1.IngressPortStatus{{Port: 443, Protocol: "TCP"}}},
		},
	}
	expectEqual(t, fc, ing)

	// 3. Resources get created for Ingress that should allow forwarding
	// cluster traffic
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		mak.Set(&ing.ObjectMeta.Annotations, AnnotationExperimentalForwardClusterTrafficViaL7IngresProxy, "true")
	})
	opts.shouldEnableForwardingClusterTrafficViaIngress = true
	expectReconciled(t, ingR, "default", "test")
	expectEqual(t, fc, expectedSTS(opts))

	// 4. Resources get cleaned up when Ingress class is unset
	mustUpdate(t, fc, "default", "test", func(ing *networkingv1.Ingress) {
		ing.Spec.IngressClassName = ptr.To("nginx")
	})
	expectReconciled(t, ingR, "default", "test")
	expectReconciled(t, ingR, "default", "test") // deleting Ingress STS requires two reconciles
	expectMissing[appsv1.StatefulSet](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Service](t, fc, "operator-ns", shortName)
	expectMissing[corev1.Secret](t, fc, "operator-ns", fullName)
}
