// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"testing"

	"slices"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/ptr"
)

func TestIngressPGReconciler(t *testing.T) {
	tsIngressClass := &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: "tailscale"},
		Spec:       networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"},
	}

	// Pre-create the ConfigMap for the ProxyGroup
	pgConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pg-ingress-config",
			Namespace: "operator-ns",
		},
		BinaryData: map[string][]byte{
			"serve-config.json": []byte(`{"Services":{}}`),
		},
	}

	fc := fake.NewFakeClient(tsIngressClass, pgConfigMap)
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	lc := &fakeLocalClient{
		status: &ipnstate.Status{
			Self: &ipnstate.PeerStatus{
				DNSName: "operator.tailnetxyz.ts.net.",
			},
		},
	}
	ingPGR := &IngressPGReconciler{
		Client:      fc,
		tsClient:    ft,
		tsnetServer: fakeTsnetServer,
		defaultTags: []string{"tag:k8s"},
		tsNamespace: "operator-ns",
		logger:      zl.Sugar(),
		recorder:    record.NewFakeRecorder(10),
		lc:          lc,
	}

	// Test 1: Default tags
	ing := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "test-pg",
			},
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
				{Hosts: []string{"my-svc.tailnetxyz.ts.net"}},
			},
		},
	}
	mustCreate(t, fc, ing)

	// Verify initial reconciliation
	expectReconciled(t, ingPGR, "default", "test-ingress")

	// Get and verify the ConfigMap was updated
	cm := &corev1.ConfigMap{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      "test-pg-ingress-config",
		Namespace: "operator-ns",
	}, cm); err != nil {
		t.Fatalf("getting ConfigMap: %v", err)
	}

	cfg := &ipn.ServeConfig{}
	if err := json.Unmarshal(cm.BinaryData[serveConfigKey], cfg); err != nil {
		t.Fatalf("unmarshaling serve config: %v", err)
	}

	if cfg.Services["my-svc"] == nil {
		t.Error("expected serve config to contain VIPService configuration")
	}

	// Verify VIPService uses default tags
	vipSvc, err := ft.getVIPServiceByName(context.Background(), "my-svc")
	if err != nil {
		t.Fatalf("getting VIPService: %v", err)
	}
	if vipSvc == nil {
		t.Fatal("VIPService not created")
	}
	wantTags := []string{"tag:k8s"} // default tags
	if !slices.Equal(vipSvc.Tags, wantTags) {
		t.Errorf("incorrect VIPService tags: got %v, want %v", vipSvc.Tags, wantTags)
	}

	// Test 2: Custom tags
	mustUpdate(t, fc, "default", "test-ingress", func(ing *networkingv1.Ingress) {
		ing.Annotations["tailscale.com/tags"] = "tag:custom,tag:test"
	})
	expectReconciled(t, ingPGR, "default", "test-ingress")

	// Verify VIPService uses custom tags
	vipSvc, err = ft.getVIPServiceByName(context.Background(), "my-svc")
	if err != nil {
		t.Fatalf("getting VIPService: %v", err)
	}
	if vipSvc == nil {
		t.Fatal("VIPService not created")
	}
	wantTags = []string{"tag:custom", "tag:test"} // custom tags only
	gotTags := slices.Clone(vipSvc.Tags)
	slices.Sort(gotTags)
	slices.Sort(wantTags)
	if !slices.Equal(gotTags, wantTags) {
		t.Errorf("incorrect VIPService tags: got %v, want %v", gotTags, wantTags)
	}

	// Delete the Ingress and verify cleanup
	if err := fc.Delete(context.Background(), ing); err != nil {
		t.Fatalf("deleting Ingress: %v", err)
	}

	expectReconciled(t, ingPGR, "default", "test-ingress")

	// Verify the ConfigMap was cleaned up
	cm = &corev1.ConfigMap{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      "test-pg-ingress-config",
		Namespace: "operator-ns",
	}, cm); err != nil {
		t.Fatalf("getting ConfigMap: %v", err)
	}

	cfg = &ipn.ServeConfig{}
	if err := json.Unmarshal(cm.BinaryData[serveConfigKey], cfg); err != nil {
		t.Fatalf("unmarshaling serve config: %v", err)
	}

	if len(cfg.Services) > 0 {
		t.Error("serve config not cleaned up")
	}
}
