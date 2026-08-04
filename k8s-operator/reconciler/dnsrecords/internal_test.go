// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package dnsrecords

import (
	"testing"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetClusterIPServiceIPs(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}

	r := &Reconciler{
		logger: zl.Sugar(),
	}

	testSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP},
	}

	// Test invalid IP format
	testSvc.Spec.ClusterIP = "invalid-ip"
	_, _, err = r.getClusterIPServiceIPs(testSvc, zl.Sugar())
	if err == nil {
		t.Error("expected error for invalid IP format")
	}

	// Test valid IP
	testSvc.Spec.ClusterIP = "10.0.100.50"
	ip4s, ip6s, err := r.getClusterIPServiceIPs(testSvc, zl.Sugar())
	if err != nil {
		t.Errorf("unexpected error for valid IP: %v", err)
	}
	if len(ip4s) != 1 || ip4s[0] != "10.0.100.50" {
		t.Errorf("expected IPv4 address 10.0.100.50, got %v", ip4s)
	}
	if len(ip6s) != 0 {
		t.Errorf("expected no IPv6 addresses, got %v", ip6s)
	}
}
