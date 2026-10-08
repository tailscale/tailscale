// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/client/tailscale/v2"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

// TestHAServiceCleanupOnAnnotationRemoved checks that removing the
// tailscale.com/proxy-group annotation from a Service that is exposed on a
// ProxyGroup cleans up the corresponding Tailscale Service and removes the
// operator's finalizer, rather than leaking the Tailscale Service and wedging
// the Service on delete.
func TestHAServiceCleanupOnAnnotationRemoved(t *testing.T) {
	if tsClient == nil {
		t.Skip("TestHAServiceCleanupOnAnnotationRemoved requires a working tailnet client")
	}
	t.Parallel()

	nginx := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, nginx)

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("ingress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeIngress,
		},
	}
	createAndCleanup(t, kubeClient, pg)

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("test-svc"),
			Namespace: ns,
			Annotations: map[string]string{
				"tailscale.com/proxy-group": pg.Name,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: new("tailscale"),
			Selector: map[string]string{
				"app.kubernetes.io/name": nginx.Name,
			},
			Ports: []corev1.ServicePort{
				{Name: "http", Protocol: "TCP", Port: 80},
			},
		},
	}
	createAndCleanup(t, kubeClient, svc)

	// The Tailscale Service is named after the Service's hostname, which
	// defaults to <namespace>-<name>.
	tsSvcName := fmt.Sprintf("svc:%s-%s", ns, svc.Name)

	forceReconcile := triggerReconcile(t,
		client.ObjectKey{Namespace: ns, Name: svc.Name},
		&corev1.Service{}, 30*time.Second)

	// Wait for the Service to be exposed and the Tailscale Service to exist.
	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		readySvc := &corev1.Service{ObjectMeta: objectMeta(ns, svc.Name)}
		if err := get(t.Context(), kubeClient, readySvc); err != nil {
			return err
		}
		for _, cond := range readySvc.Status.Conditions {
			if cond.Type == string(tsapi.IngressSvcConfigured) && cond.Status == metav1.ConditionTrue {
				if _, err := tsClient.VIPServices().Get(t.Context(), tsSvcName); err != nil {
					return fmt.Errorf("Tailscale Service %q not created yet: %w", tsSvcName, err)
				}
				return nil
			}
		}
		return fmt.Errorf("Service is not ready yet")
	}); err != nil {
		t.Fatalf("error waiting for the Service to become ready: %v", err)
	}

	// Remove the ProxyGroup annotation.
	readySvc := &corev1.Service{ObjectMeta: objectMeta(ns, svc.Name)}
	if err := get(t.Context(), kubeClient, readySvc); err != nil {
		t.Fatalf("getting Service: %v", err)
	}
	delete(readySvc.Annotations, "tailscale.com/proxy-group")
	if err := kubeClient.Update(t.Context(), readySvc); err != nil {
		t.Fatalf("removing proxy-group annotation: %v", err)
	}

	// The Tailscale Service must be cleaned up and the finalizer removed.
	if err := tstest.WaitFor(5*time.Minute, func() error {
		forceReconcile()
		if _, err := tsClient.VIPServices().Get(t.Context(), tsSvcName); err == nil {
			return fmt.Errorf("Tailscale Service %q still exists", tsSvcName)
		} else if !tailscale.IsNotFound(err) {
			return fmt.Errorf("unexpected error getting Tailscale Service %q: %w", tsSvcName, err)
		}
		cur := &corev1.Service{ObjectMeta: objectMeta(ns, svc.Name)}
		if err := get(t.Context(), kubeClient, cur); err != nil {
			return err
		}
		for _, f := range cur.Finalizers {
			if isServicePGFinalizerE2E(f) {
				return fmt.Errorf("service-pg finalizer %q not removed yet", f)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("error waiting for cleanup after annotation removal: %v", err)
	}
}

// isServicePGFinalizerE2E reports whether f is one of the HA Service
// reconciler's finalizers (either the ProxyGroup-encoded form or the bare
// legacy form). Kept local to the e2e package to avoid importing package main.
func isServicePGFinalizerE2E(f string) bool {
	_, name, ok := strings.Cut(f, "/")
	return ok && name == "service-pg-finalizer"
}
