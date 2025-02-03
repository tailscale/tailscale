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
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
)

func TestIngressPGReconciler(t *testing.T) {
	tsIngressClass := &networkingv1.IngressClass{
		ObjectMeta: metav1.ObjectMeta{Name: "tailscale"},
		Spec:       networkingv1.IngressClassSpec{Controller: "tailscale.com/ts-ingress"},
	}

	// Pre-create the ProxyGroup
	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-pg",
			Generation: 1,
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
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

	fc := fake.NewClientBuilder().
		WithScheme(tsapi.GlobalScheme).
		WithObjects(pg, pgConfigMap, tsIngressClass).
		WithStatusSubresource(pg).
		Build()
	mustUpdateStatus(t, fc, "", pg.Name, func(pg *tsapi.ProxyGroup) {
		pg.Status.Conditions = []metav1.Condition{
			{
				Type:               string(tsapi.ProxyGroupReady),
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
			},
		}
	})
	ft := &fakeTSClient{}
	fakeTsnetServer := &fakeTSNetServer{certDomains: []string{"foo.com"}}
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	lc := &fakeLocalClient{
		status: &ipnstate.Status{
			CurrentTailnet: &ipnstate.TailnetStatus{
				MagicDNSSuffix: "ts.net",
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

	if cfg.Services["svc:my-svc"] == nil {
		t.Error("expected serve config to contain VIPService configuration")
	}

	// Verify VIPService uses default tags
	vipSvc, err := ft.getVIPService(context.Background(), "svc:my-svc")
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
	vipSvc, err = ft.getVIPService(context.Background(), "svc:my-svc")
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

func TestValidateIngress(t *testing.T) {
	baseIngress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
		},
	}

	readyProxyGroup := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-pg",
			Generation: 1,
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
		Status: tsapi.ProxyGroupStatus{
			Conditions: []metav1.Condition{
				{
					Type:               string(tsapi.ProxyGroupReady),
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 1,
				},
			},
		},
	}

	tests := []struct {
		name    string
		ing     *networkingv1.Ingress
		pg      *tsapi.ProxyGroup
		wantErr string
	}{
		{
			name: "valid_ingress_with_hostname",
			ing: &networkingv1.Ingress{
				ObjectMeta: baseIngress.ObjectMeta,
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{Hosts: []string{"test.example.com"}},
					},
				},
			},
			pg: readyProxyGroup,
		},
		{
			name: "valid_ingress_with_default_hostname",
			ing:  baseIngress,
			pg:   readyProxyGroup,
		},
		{
			name: "invalid_tags",
			ing: &networkingv1.Ingress{
				ObjectMeta: metav1.ObjectMeta{
					Name:      baseIngress.Name,
					Namespace: baseIngress.Namespace,
					Annotations: map[string]string{
						AnnotationTags: "tag:invalid!",
					},
				},
			},
			pg:      readyProxyGroup,
			wantErr: "tailscale.com/tags annotation contains invalid tag \"tag:invalid!\": tag names can only contain numbers, letters, or dashes",
		},
		{
			name: "multiple_TLS_entries",
			ing: &networkingv1.Ingress{
				ObjectMeta: baseIngress.ObjectMeta,
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{Hosts: []string{"test1.example.com"}},
						{Hosts: []string{"test2.example.com"}},
					},
				},
			},
			pg:      readyProxyGroup,
			wantErr: "Ingress contains invalid TLS block [{[test1.example.com] } {[test2.example.com] }]: only a single TLS entry with a single host is allowed",
		},
		{
			name: "multiple_hosts_in_TLS_entry",
			ing: &networkingv1.Ingress{
				ObjectMeta: baseIngress.ObjectMeta,
				Spec: networkingv1.IngressSpec{
					TLS: []networkingv1.IngressTLS{
						{Hosts: []string{"test1.example.com", "test2.example.com"}},
					},
				},
			},
			pg:      readyProxyGroup,
			wantErr: "Ingress contains invalid TLS block [{[test1.example.com test2.example.com] }]: only a single TLS entry with a single host is allowed",
		},
		{
			name: "wrong_proxy_group_type",
			ing:  baseIngress,
			pg: &tsapi.ProxyGroup{
				ObjectMeta: readyProxyGroup.ObjectMeta,
				Spec: tsapi.ProxyGroupSpec{
					Type: tsapi.ProxyGroupType("foo"),
				},
				Status: readyProxyGroup.Status,
			},
			wantErr: "ProxyGroup \"test-pg\" is of type \"foo\" but must be of type \"ingress\"",
		},
		{
			name: "proxy_group_not_ready",
			ing:  baseIngress,
			pg: &tsapi.ProxyGroup{
				ObjectMeta: readyProxyGroup.ObjectMeta,
				Spec:       readyProxyGroup.Spec,
				Status: tsapi.ProxyGroupStatus{
					Conditions: []metav1.Condition{
						{
							Type:               string(tsapi.ProxyGroupReady),
							Status:             metav1.ConditionFalse,
							ObservedGeneration: 1,
						},
					},
				},
			},
			wantErr: "ProxyGroup \"test-pg\" is not ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &IngressPGReconciler{}
			err := r.validateIngress(tt.ing, tt.pg)
			if (err == nil && tt.wantErr != "") || (err != nil && err.Error() != tt.wantErr) {
				t.Errorf("validateIngress() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
