// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestHealthCheckTargetsForReadinessDualStack(t *testing.T) {
	svc := &corev1.Service{}
	svc.Spec.ClusterIPs = []string{"10.0.0.10", "fd00::10"}
	svc.Spec.Ports = []corev1.ServicePort{{Name: tsHealthCheckPortName, Port: 9002}}

	got := healthCheckTargetsForReadiness(svc, "cluster.local")
	if len(got) != 2 {
		t.Fatalf("got %d targets, want 2", len(got))
	}
	if got[0].addr != "http://10.0.0.10:9002/healthz" {
		t.Errorf("target[0] = %q, want IPv4 ClusterIP", got[0].addr)
	}
	if got[1].addr != "http://[fd00::10]:9002/healthz" {
		t.Errorf("target[1] = %q, want IPv6 ClusterIP", got[1].addr)
	}
}

func TestHealthCheckTargetsForReadinessSingleStack(t *testing.T) {
	svc := &corev1.Service{}
	svc.Spec.ClusterIPs = []string{"10.0.0.10"}
	svc.Spec.Ports = []corev1.ServicePort{{Name: tsHealthCheckPortName, Port: 9002}}

	got := healthCheckTargetsForReadiness(svc, "cluster.local")
	if len(got) != 1 || got[0].addr != "http://10.0.0.10:9002/healthz" {
		t.Fatalf("got %#v, want one IPv4 ClusterIP target", got)
	}
}

func TestPodIPForHealthCheckFamily(t *testing.T) {
	pod := &corev1.Pod{}
	pod.Status.PodIPs = []corev1.PodIP{{IP: "10.0.0.2"}, {IP: "fd00::2"}}

	got, ok := podIPForHealthCheckFamily(pod, "http://10.0.0.10:9002/healthz")
	if !ok || got != "10.0.0.2" {
		t.Fatalf("IPv4 lookup = %q, %v; want 10.0.0.2, true", got, ok)
	}

	got, ok = podIPForHealthCheckFamily(pod, "http://[fd00::10]:9002/healthz")
	if !ok || got != "fd00::2" {
		t.Fatalf("IPv6 lookup = %q, %v; want fd00::2, true", got, ok)
	}
}

func TestPodIPForHealthCheckFamilyMissingFamily(t *testing.T) {
	pod := &corev1.Pod{}
	pod.Status.PodIPs = []corev1.PodIP{{IP: "10.0.0.2"}}

	if got, ok := podIPForHealthCheckFamily(pod, "http://[fd00::10]:9002/healthz"); ok || got != "" {
		t.Fatalf("lookup = %q, %v; want empty, false", got, ok)
	}
}
