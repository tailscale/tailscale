// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package egress

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/k8s-operator/reconciler"
)

// The names and labels below are a contract with things outside this package: proxies select on the labels, the
// ProxyGroup reconciler creates the ConfigMap CMName refers to, and the egress config is keyed by tailnetSvcName. The
// rest of the package's tests build their fixtures from these helpers, so they would follow a change here rather than
// catch it; assert the literal values once.

func TestCMName(t *testing.T) {
	if got, want := CMName("pg"), "pg-egress-config"; got != want {
		t.Errorf("CMName(\"pg\") = %q, want %q", got, want)
	}
}

func TestTailnetSvcName(t *testing.T) {
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "dev", Name: "my-app"}}
	if got, want := tailnetSvcName(svc), "dev-my-app"; got != want {
		t.Errorf("tailnetSvcName = %q, want %q", got, want)
	}
}

func TestChildResourceLabels(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "dev",
			Name:        "my-app",
			Annotations: map[string]string{reconciler.AnnotationProxyGroup: "pg"},
		},
	}

	want := map[string]string{
		"tailscale.com/managed":              "true",
		"tailscale.com/parent-resource-type": "svc",
		"tailscale.com/parent-resource":      "my-app",
		"tailscale.com/parent-resource-ns":   "dev",
		"tailscale.com/proxy-group":          "pg",
		"tailscale.com/svc-type":             "egress",
	}
	got := childResourceLabels(svc)
	if len(got) != len(want) {
		t.Fatalf("got %d labels, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("label %q = %q, want %q", k, got[k], v)
		}
	}
}
