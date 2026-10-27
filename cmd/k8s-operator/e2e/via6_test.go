// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/ipn"
	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tstest"
)

const via6SiteID = 7

// via6BackendIP is the dummy IPv4 embedded in the advertised 4via6 route; it is
// never dialed.
var via6BackendIP = netip.MustParseAddr("10.0.0.1")

type via6Target struct {
	viaIP   string // e.g. "fd7a:115c:a1e0:b1a::7:a00:1"
	viaFQDN string // e.g. "10-0-0-1-via-7.<tailnet>.ts.net"
}

// TestHostSubnetRouter4via6Egress tests the operator's 4via6 egress
// using a subnet router outside the cluster (runs as a tsnet node advertising a 4via6 route).
//
// See [TestMain] for test requirements.
func TestHostSubnetRouter4via6Egress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestHostSubnetRouter4via6Egress requires a working tailnet client")
	}
	if !clusterIPv6Support {
		t.Skip("4via6 egress requires an IPv6-capable cluster")
	}
	t.Parallel()

	target := startVia6SubnetRouter(t)
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

// See [TestHostSubnetRouter4via6Egress] and [TestMain] for test requirements.
func TestHostSubnetRouter4via6HAEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestHostSubnetRouter4via6HAEgress requires a working tailnet client")
	}
	if !clusterIPv6Support {
		t.Skip("4via6 egress requires an IPv6-capable cluster")
	}
	t.Parallel()

	target := startVia6SubnetRouter(t)
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

// startVia6SubnetRouter brings up a tsnet node on the test host that advertises a
// 4via6 route and acts as a subnet router, serving the forwarded flow in-process
// via a RegisterFallbackTCPHandler. It returns the egress target's tailnet IP and FQDN.
func startVia6SubnetRouter(t *testing.T) via6Target {
	t.Helper()

	srv := newTailnetNode(t, tsClient, generateName("test-4via6-router"))
	srv.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		// Mock the backend.
		return func(c net.Conn) {
			defer c.Close()
			req, err := http.ReadRequest(bufio.NewReader(c))
			if err != nil {
				return
			}
			resp := http.Response{StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, Close: true, Request: req}
			if err := resp.Write(c); err != nil {
				t.Logf("writing 4via6 response: %v", err)
			}
		}, true
	})

	via, err := tsaddr.MapVia(via6SiteID, netip.PrefixFrom(via6BackendIP, 32))
	if err != nil {
		t.Fatalf("computing 4via6 route for %s: %v", via6BackendIP, err)
	}

	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("getting subnet router local client: %v", err)
	}
	if _, err := lc.EditPrefs(t.Context(), &ipn.MaskedPrefs{
		AdvertiseRoutesSet: true,
		Prefs: ipn.Prefs{
			AdvertiseRoutes: []netip.Prefix{via},
		},
	}); err != nil {
		t.Fatalf("advertising 4via6 route %s: %v", via, err)
	}

	return via6Target{
		viaIP:   via.Addr().String(),
		viaFQDN: via6FQDN(t, via6BackendIP, via6SiteID, srv),
	}
}

// TestConnector4via6Egress tests that the egress proxy can reach a Connector
// subnet router which advertises a 4via6 route. The Connector is created in
// the same cluster.
//
// This test requires a dual-stack cluster because the destination must be
// an IPv4 ClusterIP, while the egress proxy must be in a cluster that supports
// IPv6 in order to successfully forward 4via6 traffic. To test using a
// single-stack IPv6 cluster, see [TestHostSubnetRouter4via6Egress] instead.
//
// See [TestMain] for test requirements.
func TestConnector4via6Egress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnector4via6Egress requires a working tailnet client")
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
// Service, creates a Connector subnet router advertising a 4via6 route for the
// Service's IPv4 ClusterIP, waits for the Connector to be ready, and
// returns the backend's 4via6 tailnet IP and FQDN.
func setup4via6Backend(t *testing.T) via6Target {
	t.Helper()

	deploy := nginxDeployment(ns)
	createAndCleanup(t, kubeClient, deploy)

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

	// MapVia needs an IPv4 CIDR, so pick the backend's IPv4 ClusterIP.
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

// applyAcceptRoutesProxyClass creates a ProxyClass that enables AcceptRoutes so
// that egress proxies install the host subnet router's advertised 4via6 route,
// waits for it to be ready, and returns it.
func applyAcceptRoutesProxyClass(t *testing.T) *tsapi.ProxyClass {
	t.Helper()

	var env []tsapi.Env
	if *fDevcontrol {
		env = []tsapi.Env{{
			Name:  "TS_DEBUG_ACME_DIRECTORY_URL",
			Value: "https://pebble:14000/dir",
		}}
	}
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{Name: generateName("accept-routes")},
		Spec: tsapi.ProxyClassSpec{
			UseLetsEncryptStagingEnvironment: !*fDevcontrol,
			TailscaleConfig: &tsapi.TailscaleConfig{
				AcceptRoutes: true,
			},
			StatefulSet: &tsapi.StatefulSet{
				Pod: &tsapi.Pod{
					TailscaleInitContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
					},
					TailscaleContainer: &tsapi.Container{
						ImagePullPolicy: "IfNotPresent",
						Env:             env,
					},
				},
			},
		},
	}
	createAndCleanup(t, kubeClient, pc)
	waitForProxyClassReady(t, pc.Name)

	return pc
}
