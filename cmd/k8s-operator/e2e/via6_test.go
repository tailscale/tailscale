// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/ipn"
	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/net/tsaddr"
)

// via6SiteID is the 4via6 site ID used by the 4via6 egress tests.
const via6SiteID = 7

// via6BackendIP is the IPv4 embedded in the 4via6 route the host subnet router
// advertises. The tsnet router serves the flow in-process (see
// startVia6SubnetRouter), so nothing ever dials this address; it only needs to be
// a non-loopback IPv4 that passes viaTargetAllowed (ipn/ipnlocal/via.go), which is
// why a dummy RFC1918 address works and no TS_4VIA6_ALLOW_LOCAL is required.
var via6BackendIP = netip.MustParseAddr("10.0.0.1")

// via6Target holds the two forms an egress Service can use to point at a 4via6
// destination: the raw synthetic IPv6 address, and the hyphenated MagicDNS name.
type via6Target struct {
	viaIP   string // e.g. "fd7a:115c:a1e0:b1a::7:a00:1"
	viaFQDN string // e.g. "10-0-0-1-via-7.<tailnet>.ts.net"
}

// TestHostSubnetRouter4via6Egress exercises the operator's 4via6 egress datapath
// without needing a dual-stack cluster. The subnet router runs on the test host
// as a tsnet node advertising a 4via6 route and serving the forwarded flow
// in-process; a standalone egress Service targets that 4via6 destination (by raw
// via6 IP and by hyphenated "-via-" MagicDNS name). A cluster pod must then reach
// the backend through the host subnet router.
//
// It runs on a single-stack IPv6 cluster (not IPv4-only): the egress proxy still
// DNATs to the via6 IPv6 destination, so the cluster must support IPv6 and the
// proxy Nodes must have IPv6 NAT (ip6tables/nft). Unlike [TestConnector4via6Egress]
// it does not require dual-stack, because the subnet router is on the test host
// rather than an in-cluster Connector fronting a dual-stack backend ClusterIP.
//
// See [TestMain] for test requirements.
func TestHostSubnetRouter4via6Egress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestHostSubnetRouter4via6Egress requires a working tailnet client")
	}
	if *fCluster {
		t.Skip("4via6 does not work in a kind cluster; run against a real cluster (omit --cluster)")
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
	if *fCluster {
		t.Skip("4via6 does not work in a kind cluster; run against a real cluster (omit --cluster)")
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
// 4via6 route and serves the forwarded flow in-process, acting as a subnet router.
// It returns the two forms a 4via6 egress target can take.
//
// The node serves the via6 flow with a RegisterFallbackTCPHandler rather than
// forwarding to an external backend: netstack hands any TCP flow to the node that
// no Listen matches (which the inbound 4via6 flow is) to this handler. That keeps
// everything in-process — no loopback backend, no container, and no
// TS_4VIA6_ALLOW_LOCAL (the embedded IPv4 is a dummy non-loopback address that is
// never dialed).
func startVia6SubnetRouter(t *testing.T) via6Target {
	t.Helper()

	// Pass t.Logf so the router's netstack logs its 4via6 forwarding decisions,
	// which are otherwise silently dropped.
	srv := newTailnetNode(t, tsClient, generateName("test-4via6-router"), t.Logf)
	srv.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		return serveOK, true
	})

	via, err := tsaddr.MapVia(via6SiteID, netip.PrefixFrom(via6BackendIP, 32))
	if err != nil {
		t.Fatalf("computing 4via6 route for %s: %v", via6BackendIP, err)
	}

	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("getting subnet router local client: %v", err)
	}
	// Advertise the 4via6 route. It is auto-approved by the via6 range in
	// acl.hujson for tag:k8s.
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

// serveOK reads one HTTP request from c and replies 200 OK, then closes c. It is
// the in-process backend for the 4via6 subnet router.
func serveOK(c net.Conn) {
	defer c.Close()
	if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
		return
	}
	io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// applyAcceptRoutesProxyClass creates a ProxyClass that enables AcceptRoutes so
// that egress proxies install the host subnet router's advertised 4via6 route,
// waits for it to be ready, and returns it. Apart from AcceptRoutes it matches
// the suite's default ProxyClass (see applyDefaultProxyClass in setup.go).
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
