// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
)

// See [TestMain] for test requirements.
func TestEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestEgress requires a working tailnet client")
	}
	t.Parallel()

	t.Run("IPv4", func(t *testing.T) {
		if !clusterIPv4Support {
			t.Skip("cluster does not support IPv4")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip": tnTarget.ipv4,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		testEgressIsReachable(t, egressURL(svc.Name))
	})

	t.Run("IPv6", func(t *testing.T) {
		if !clusterIPv6Support {
			t.Skip("cluster does not support IPv6")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip": tnTarget.ipv6,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		testEgressIsReachable(t, egressURL(svc.Name))
	})

	t.Run("FQDN", func(t *testing.T) {
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-fqdn": tnTarget.fqdn,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		testEgressIsReachable(t, egressURL(svc.Name))
	})
}

// See [TestMain] for test requirements.
func TestHAEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestHAEgress requires a working tailnet client")
	}
	t.Parallel()

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("egress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type: tsapi.ProxyGroupTypeEgress,
		},
	}
	createAndCleanup(t, kubeClient, pg)

	t.Run("IPv4", func(t *testing.T) {
		if !clusterIPv4Support {
			t.Skip("cluster does not support IPv4")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip":  tnTarget.ipv4,
			"tailscale.com/proxy-group": pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		testEgressIsReachable(t, egressURL(svc.Name))
	})

	t.Run("IPv6", func(t *testing.T) {
		if !clusterIPv6Support {
			t.Skip("cluster does not support IPv6")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip":  tnTarget.ipv6,
			"tailscale.com/proxy-group": pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		testEgressIsReachable(t, egressURL(svc.Name))
	})

	t.Run("FQDN", func(t *testing.T) {
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-fqdn": tnTarget.fqdn,
			"tailscale.com/proxy-group":  pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		testEgressIsReachable(t, egressURL(svc.Name))
	})
}

// See [TestMain] for test requirements.
func TestHAEgressMultiTailnet(t *testing.T) {
	if tnClient == nil || secondTNClient == nil {
		t.Skip("TestHAEgressMultiTailnet requires a working tailnet client for a first and second tailnet")
	}
	t.Parallel()

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("egress"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:    tsapi.ProxyGroupTypeEgress,
			Tailnet: "second-tailnet",
		},
	}
	createAndCleanup(t, kubeClient, pg)
	if err := verifyProxyGroupTailnet(t, pg, secondTNClient); err != nil {
		t.Fatalf("verifying ProxyGroup %s is registered to the correct tailnet: %v", pg.Name, err)
	}

	svc := egressService(generateName("test-egress"), map[string]string{
		"tailscale.com/tailnet-fqdn": secondTNTarget.fqdn,
		"tailscale.com/proxy-group":  pg.Name,
	})
	createAndCleanup(t, kubeClient, svc)
	waitForEgress(t, svc.Name, pgEgressReady)
	testEgressIsReachable(t, egressURL(svc.Name))
}

func pgEgressReady(svc *corev1.Service) bool {
	cond := kube.GetServiceCondition(svc, tsapi.EgressSvcReady)
	return cond != nil && cond.Status == metav1.ConditionTrue
}
