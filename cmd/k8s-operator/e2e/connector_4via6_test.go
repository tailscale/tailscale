// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
)

// TestConnector4via6Egress exercises the 4via6 datapath end-to-end using a
// standalone egress proxy: a Connector subnet router advertises a 4via6 route
// covering an in-cluster IPv4 backend, and a standalone egress Service targets
// that 4via6 destination (by raw via6 IP and by hyphenated "-via-" MagicDNS
// name). A cluster pod must then reach the backend through the subnet router.
//
// This test needs a dual-stack cluster, because it derives the 4via6 route from
// the backend's IPv4 ClusterIP while the egress proxy requires IPv6. For a
// single-stack IPv6 cluster, see [TestHostSubnetRouter4via6Egress] instead.
//
// See [TestMain] for test requirements.
func TestConnector4via6Egress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnector4via6Egress requires a working tailnet client")
	}
	if *fCluster {
		t.Skip("4via6 does not work in a kind cluster; run against a real dual-stack cluster")
	}
	if !clusterIPv4Support || !clusterIPv6Support {
		t.Skip("TestConnector4via6Egress requires a dual-stack cluster; for a single-stack IPv6 cluster see TestHostSubnetRouter4via6Egress")
	}
	t.Parallel()

	target := setup4via6Backend(t)
	proxyClass := applyAcceptRoutesProxyClass(t)

	t.Run("ViaIP", func(t *testing.T) {
		svc := egressService(generateName("test-4via6"), map[string]string{
			"tailscale.com/tailnet-ip":  target.viaIP,
			"tailscale.com/proxy-class": proxyClass.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})

	t.Run("ViaFQDN", func(t *testing.T) {
		svc := egressService(generateName("test-4via6"), map[string]string{
			"tailscale.com/tailnet-fqdn": target.viaFQDN,
			"tailscale.com/proxy-class":  proxyClass.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})
}

// See [TestConnector4via6Egress] and [TestMain] for test requirements.
func TestConnector4via6HAEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnector4via6HAEgress requires a working tailnet client")
	}
	if *fCluster {
		t.Skip("4via6 does not work in a kind cluster; run against a real dual-stack cluster (omit --cluster)")
	}
	if !clusterIPv4Support || !clusterIPv6Support {
		t.Skip("TestConnector4via6HAEgress requires a dual-stack cluster; for a single-stack IPv6 cluster see TestHostSubnetRouter4via6HAEgress")
	}
	t.Parallel()

	target := setup4via6Backend(t)
	proxyClass := applyAcceptRoutesProxyClass(t)

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("egress-4via6"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:       tsapi.ProxyGroupTypeEgress,
			ProxyClass: proxyClass.Name,
		},
	}
	createAndCleanup(t, kubeClient, pg)

	t.Run("ViaIP", func(t *testing.T) {
		svc := egressService(generateName("test-4via6"), map[string]string{
			"tailscale.com/tailnet-ip":  target.viaIP,
			"tailscale.com/proxy-group": pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})

	t.Run("ViaFQDN", func(t *testing.T) {
		svc := egressService(generateName("test-4via6"), map[string]string{
			"tailscale.com/tailnet-fqdn": target.viaFQDN,
			"tailscale.com/proxy-group":  pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})
}

// setup4via6Backend deploys an nginx backend behind a dual-stack ClusterIP
// Service, creates a Connector subnet router advertising the 4via6 route that
// covers that Service's IPv4 ClusterIP, waits for the Connector to be ready, and
// returns the two forms a 4via6 egress target can take.
func setup4via6Backend(t *testing.T) via6Target {
	t.Helper()

	deploy := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, deploy)

	// The backend is a normal dual-stack Service. We derive the 4via6 route from
	// its IPv4 ClusterIP below (MapVia requires an IPv4), but the Service itself
	// is left dual-stack so the setup is representative of a real cluster.
	backendSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generateName("nginx-backend"),
			Namespace: ns,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeClusterIP,
			Selector: deploy.Spec.Selector.MatchLabels,
			Ports: []corev1.ServicePort{{
				Name:     "http",
				Protocol: corev1.ProtocolTCP,
				Port:     egressPort,
			}},
			IPFamilyPolicy: new(corev1.IPFamilyPolicyPreferDualStack),
		},
	}
	createAndCleanup(t, kubeClient, backendSvc)

	// MapVia needs an IPv4 CIDR, so pick the backend's IPv4 ClusterIP
	// specifically (Spec.ClusterIP may be the IPv6 one on a dual-stack Service).
	var ip netip.Addr
	if err := tstest.WaitFor(time.Minute, func() error {
		svc := &corev1.Service{ObjectMeta: objectMeta(ns, backendSvc.Name)}
		if err := get(t.Context(), kubeClient, svc); err != nil {
			return err
		}
		for _, clusterIP := range svc.Spec.ClusterIPs {
			addr, err := netip.ParseAddr(clusterIP)
			if err != nil {
				return fmt.Errorf("parsing backend ClusterIP %q: %w", clusterIP, err)
			}
			if addr.Is4() {
				ip = addr
				return nil
			}
		}
		return fmt.Errorf("backend Service has no IPv4 ClusterIP yet (got %v)", svc.Spec.ClusterIPs)
	}); err != nil {
		t.Fatalf("waiting for backend IPv4 ClusterIP: %v", err)
	}
	t.Logf("backend IPv4 ClusterIP: %s", ip)

	via, err := tsaddr.MapVia(via6SiteID, netip.PrefixFrom(ip, 32))
	if err != nil {
		t.Fatalf("computing 4via6 route for %s: %v", ip, err)
	}

	// Connector subnet router advertising the 4via6 route. The route is
	// auto-approved by the via6 range in acl.hujson.
	cn := &tsapi.Connector{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("subnet-router-4via6"),
		},
		Spec: tsapi.ConnectorSpec{
			SubnetRouter: &tsapi.SubnetRouter{
				AdvertiseRoutes: []tsapi.Route{tsapi.Route(via.String())},
			},
			ProxyClass: "default",
		},
	}
	createAndCleanup(t, kubeClient, cn)
	waitForConnectorReady(t, cn.Name)

	return via6Target{
		viaIP:   via.Addr().String(),
		viaFQDN: via6FQDN(t, ip, via6SiteID, tnClient),
	}
}
