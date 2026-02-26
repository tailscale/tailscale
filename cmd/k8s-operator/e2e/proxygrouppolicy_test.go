// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/types/ptr"
)

// See [TestMain] for test requirements.
func TestProxyGroupPolicy(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestProxyGroupPolicy requires a working tailnet client")
	}

	// Apply deny-all policy
	denyAllPolicy := &tsapi.ProxyGroupPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-all",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: tsapi.ProxyGroupPolicySpec{
			Ingress: []string{},
			Egress:  []string{},
		},
	}

	createAndCleanup(t, kubeClient, denyAllPolicy)
	<-time.After(time.Second * 2)

	// Attempt to create an egress Service within the default namespace, the above policy should
	// reject it.
	egressService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "egress-to-proxy-group",
			Namespace: metav1.NamespaceDefault,
			Annotations: map[string]string{
				"tailscale.com/tailnet-fqdn": "test.something.ts.net",
				"tailscale.com/proxy-group":  "test",
			},
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Ports: []corev1.ServicePort{
				{
					Port:     8080,
					Protocol: corev1.ProtocolTCP,
					Name:     "http",
				},
			},
		},
	}

	err := createAndCleanupErr(t, kubeClient, egressService)
	switch {
	case err != nil && strings.Contains(err.Error(), "ValidatingAdmissionPolicy"):
	case err != nil:
		t.Fatalf("expected forbidden error, got: %v", err)
	default:
		t.Fatal("expected error when creating egress service")
	}

	// Attempt to create an ingress Service within the default namespace, the above policy should
	// reject it.
	ingressService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-to-proxy-group",
			Namespace: metav1.NamespaceDefault,
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "test",
			},
		},
		Spec: corev1.ServiceSpec{
			Type:              corev1.ServiceTypeLoadBalancer,
			LoadBalancerClass: ptr.To("tailscale"),
			Ports: []corev1.ServicePort{
				{
					Port:     8080,
					Protocol: corev1.ProtocolTCP,
					Name:     "http",
				},
			},
		},
	}

	err = createAndCleanupErr(t, kubeClient, ingressService)
	switch {
	case err != nil && strings.Contains(err.Error(), "ValidatingAdmissionPolicy"):
	case err != nil:
		t.Fatalf("expected forbidden error, got: %v", err)
	default:
		t.Fatal("expected error when creating ingress service")
	}

	// Attempt to create an Ingress within the default namespace, the above policy should reject it
	ingress := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-to-proxy-group",
			Namespace: metav1.NamespaceDefault,
			Annotations: map[string]string{
				"tailscale.com/proxy-group": "test",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: ptr.To("tailscale"),
			DefaultBackend: &networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: "nginx",
					Port: networkingv1.ServiceBackendPort{
						Number: 80,
					},
				},
			},
			TLS: []networkingv1.IngressTLS{
				{
					Hosts: []string{"nginx"},
				},
			},
		},
	}

	err = createAndCleanupErr(t, kubeClient, ingress)
	switch {
	case err != nil && strings.Contains(err.Error(), "ValidatingAdmissionPolicy"):
	case err != nil:
		t.Fatalf("expected forbidden error, got: %v", err)
	default:
		t.Fatal("expected error when creating ingress")
	}

	// Add policy to allow ingress/egress using the "test" proxy-group. This should be merged with the deny-all
	// policy so they do not conflict.
	allowTestPolicy := &tsapi.ProxyGroupPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-test",
			Namespace: metav1.NamespaceDefault,
		},
		Spec: tsapi.ProxyGroupPolicySpec{
			Ingress: []string{"test"},
			Egress:  []string{"test"},
		},
	}

	createAndCleanup(t, kubeClient, allowTestPolicy)
	<-time.After(time.Second * 2)

	// With this policy in place, the above ingress/egress resources should be allowed to be created.
	createAndCleanup(t, kubeClient, egressService)
	createAndCleanup(t, kubeClient, ingressService)
	createAndCleanup(t, kubeClient, ingress)
}
