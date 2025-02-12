// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	"slices"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

func TestIngressPGReconciler(t *testing.T) {
	ingPGR, fc, ft := setupIngressTest(t)

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
	verifyServeConfig(t, fc, "svc:my-svc", false)
	verifyVIPService(t, ft, "svc:my-svc", []string{"443"})

	mustUpdate(t, fc, "default", "test-ingress", func(ing *networkingv1.Ingress) {
		ing.Annotations["tailscale.com/tags"] = "tag:custom,tag:test"
	})
	expectReconciled(t, ingPGR, "default", "test-ingress")

	// Verify VIPService uses custom tags
	vipSvc, err := ft.GetVIPService(context.Background(), "svc:my-svc")
	if err != nil {
		t.Fatalf("getting VIPService: %v", err)
	}
	if vipSvc == nil {
		t.Fatal("VIPService not created")
	}
	wantTags := []string{"tag:custom", "tag:test"} // custom tags only
	gotTags := slices.Clone(vipSvc.Tags)
	slices.Sort(gotTags)
	slices.Sort(wantTags)
	if !slices.Equal(gotTags, wantTags) {
		t.Errorf("incorrect VIPService tags: got %v, want %v", gotTags, wantTags)
	}

	// Create second Ingress
	ing2 := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-other-ingress",
			Namespace: "default",
			UID:       types.UID("5678-UID"),
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
				{Hosts: []string{"my-other-svc.tailnetxyz.ts.net"}},
			},
		},
	}
	mustCreate(t, fc, ing2)

	// Verify second Ingress reconciliation
	expectReconciled(t, ingPGR, "default", "my-other-ingress")
	verifyServeConfig(t, fc, "svc:my-other-svc", false)
	verifyVIPService(t, ft, "svc:my-other-svc", []string{"443"})

	// Verify first Ingress is still working
	verifyServeConfig(t, fc, "svc:my-svc", false)
	verifyVIPService(t, ft, "svc:my-svc", []string{"443"})

	// Delete second Ingress
	if err := fc.Delete(context.Background(), ing2); err != nil {
		t.Fatalf("deleting second Ingress: %v", err)
	}
	expectReconciled(t, ingPGR, "default", "my-other-ingress")

	// Verify second Ingress cleanup
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

	// Verify first Ingress is still configured
	if cfg.Services["svc:my-svc"] == nil {
		t.Error("first Ingress service config was incorrectly removed")
	}
	// Verify second Ingress was cleaned up
	if cfg.Services["svc:my-other-svc"] != nil {
		t.Error("second Ingress service config was not cleaned up")
	}

	// Delete the first Ingress and verify cleanup
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

func TestIngressPGReconciler_HTTPEndpoint(t *testing.T) {
	ingPGR, fc, ft := setupIngressTest(t)

	// Create test Ingress with HTTP endpoint enabled
	ing := &networkingv1.Ingress{
		TypeMeta: metav1.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-ingress",
			Namespace: "default",
			UID:       types.UID("1234-UID"),
			Annotations: map[string]string{
				"tailscale.com/proxy-group":   "test-pg",
				"tailscale.com/http-endpoint": "enabled",
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
				{Hosts: []string{"my-svc"}},
			},
		},
	}
	if err := fc.Create(context.Background(), ing); err != nil {
		t.Fatal(err)
	}

	// Verify initial reconciliation with HTTP enabled
	expectReconciled(t, ingPGR, "default", "test-ingress")
	verifyVIPService(t, ft, "svc:my-svc", []string{"80", "443"})
	verifyServeConfig(t, fc, "svc:my-svc", true)

	// Verify Ingress status
	ing = &networkingv1.Ingress{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      "test-ingress",
		Namespace: "default",
	}, ing); err != nil {
		t.Fatal(err)
	}

	wantStatus := []networkingv1.IngressPortStatus{
		{Port: 443, Protocol: "TCP"},
		{Port: 80, Protocol: "TCP"},
	}
	if !reflect.DeepEqual(ing.Status.LoadBalancer.Ingress[0].Ports, wantStatus) {
		t.Errorf("incorrect status ports: got %v, want %v",
			ing.Status.LoadBalancer.Ingress[0].Ports, wantStatus)
	}

	// Remove HTTP endpoint annotation
	mustUpdate(t, fc, "default", "test-ingress", func(ing *networkingv1.Ingress) {
		delete(ing.Annotations, "tailscale.com/http-endpoint")
	})

	// Verify reconciliation after removing HTTP
	expectReconciled(t, ingPGR, "default", "test-ingress")
	verifyVIPService(t, ft, "svc:my-svc", []string{"443"})
	verifyServeConfig(t, fc, "svc:my-svc", false)

	// Verify Ingress status
	ing = &networkingv1.Ingress{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      "test-ingress",
		Namespace: "default",
	}, ing); err != nil {
		t.Fatal(err)
	}

	wantStatus = []networkingv1.IngressPortStatus{
		{Port: 443, Protocol: "TCP"},
	}
	if !reflect.DeepEqual(ing.Status.LoadBalancer.Ingress[0].Ports, wantStatus) {
		t.Errorf("incorrect status ports: got %v, want %v",
			ing.Status.LoadBalancer.Ingress[0].Ports, wantStatus)
	}
}

func verifyVIPService(t *testing.T, ft *fakeTSClient, serviceName string, wantPorts []string) {
	t.Helper()
	vipSvc, err := ft.GetVIPService(context.Background(), tailcfg.ServiceName(serviceName))
	if err != nil {
		t.Fatalf("getting VIPService %q: %v", serviceName, err)
	}
	if vipSvc == nil {
		t.Fatalf("VIPService %q not created", serviceName)
	}
	gotPorts := slices.Clone(vipSvc.Ports)
	slices.Sort(gotPorts)
	slices.Sort(wantPorts)
	if !slices.Equal(gotPorts, wantPorts) {
		t.Errorf("incorrect ports for VIPService %q: got %v, want %v", serviceName, gotPorts, wantPorts)
	}
}

func verifyServeConfig(t *testing.T, fc client.Client, serviceName string, wantHTTP bool) {
	t.Helper()

	cm := &corev1.ConfigMap{}
	if err := fc.Get(context.Background(), types.NamespacedName{
		Name:      "test-pg-ingress-config",
		Namespace: "operator-ns",
	}, cm); err != nil {
		t.Fatalf("getting ConfigMap: %v", err)
	}

	cfg := &ipn.ServeConfig{}
	if err := json.Unmarshal(cm.BinaryData["serve-config.json"], cfg); err != nil {
		t.Fatalf("unmarshaling serve config: %v", err)
	}

	t.Logf("Looking for service %q in config: %+v", serviceName, cfg)

	svc := cfg.Services[tailcfg.ServiceName(serviceName)]
	if svc == nil {
		t.Fatalf("service %q not found in serve config, services: %+v", serviceName, maps.Keys(cfg.Services))
	}

	wantHandlers := 1
	if wantHTTP {
		wantHandlers = 2
	}

	// Check TCP handlers
	if len(svc.TCP) != wantHandlers {
		t.Errorf("incorrect number of TCP handlers for service %q: got %d, want %d", serviceName, len(svc.TCP), wantHandlers)
	}
	if wantHTTP {
		if h, ok := svc.TCP[uint16(80)]; !ok {
			t.Errorf("HTTP (port 80) handler not found for service %q", serviceName)
		} else if !h.HTTP {
			t.Errorf("HTTP not enabled for port 80 handler for service %q", serviceName)
		}
	}
	if h, ok := svc.TCP[uint16(443)]; !ok {
		t.Errorf("HTTPS (port 443) handler not found for service %q", serviceName)
	} else if !h.HTTPS {
		t.Errorf("HTTPS not enabled for port 443 handler for service %q", serviceName)
	}

	// Check Web handlers
	if len(svc.Web) != wantHandlers {
		t.Errorf("incorrect number of Web handlers for service %q: got %d, want %d", serviceName, len(svc.Web), wantHandlers)
	}
}

func setupIngressTest(t *testing.T) (*IngressPGReconciler, client.Client, *fakeTSClient) {
	t.Helper()

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

	// Set ProxyGroup status to ready
	pg.Status.Conditions = []metav1.Condition{
		{
			Type:               string(tsapi.ProxyGroupReady),
			Status:             metav1.ConditionTrue,
			ObservedGeneration: 1,
		},
	}
	if err := fc.Status().Update(context.Background(), pg); err != nil {
		t.Fatal(err)
	}

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

	return ingPGR, fc, ft
}
