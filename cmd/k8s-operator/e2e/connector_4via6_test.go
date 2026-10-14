// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

// via6SiteID is the 4via6 site ID used by the Connector tests.
const via6SiteID = 7

// TestConnector4via6Egress exercises the 4via6 datapath end-to-end using a
// standalone egress proxy: a Connector subnet router advertises a 4via6 route
// covering an in-cluster IPv4 backend, and a standalone egress Service targets
// that 4via6 destination (by raw via6 IP and by hyphenated "-via-" MagicDNS
// name). A cluster pod must then reach the backend through the subnet router.
//
// This test only runs against a real dual-stack cluster.
//
// See [TestMain] for test requirements.
func TestConnector4via6Egress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnector4via6Egress requires a working tailnet client")
	}
	if *fCluster {
		t.Skip("4via6 does not work in a kind cluster; run against a real dual-stack cluster")
	}
	if !clusterIPv6Support {
		t.Skip("4via6 egress requires a cluster that supports IPv6")
	}
	t.Parallel()

	target := setup4via6Backend(t)
	proxyClass := acceptRoutesProxyClass(t)

	t.Run("ViaIP", func(t *testing.T) {
		svc := egressService(generateName("test-4via6"), map[string]string{
			"tailscale.com/tailnet-ip":  target.viaIP,
			"tailscale.com/proxy-class": proxyClass,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})

	t.Run("ViaFQDN", func(t *testing.T) {
		svc := egressService(generateName("test-4via6"), map[string]string{
			"tailscale.com/tailnet-fqdn": target.viaFQDN,
			"tailscale.com/proxy-class":  proxyClass,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})
}

// See [TestMain] for test requirements.
func TestConnector4via6HAEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestConnector4via6HAEgress requires a working tailnet client")
	}
	if *fCluster {
		t.Skip("4via6 does not work in a kind cluster; run against a real dual-stack cluster (omit --cluster)")
	}
	if !clusterIPv6Support {
		t.Skip("4via6 egress requires a dual-stack cluster")
	}
	t.Parallel()

	target := setup4via6Backend(t)
	proxyClass := acceptRoutesProxyClass(t)

	pg := &tsapi.ProxyGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("egress-4via6"),
		},
		Spec: tsapi.ProxyGroupSpec{
			Type:       tsapi.ProxyGroupTypeEgress,
			ProxyClass: proxyClass,
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

// via6Target holds the two forms an egress Service can use to point at a 4via6
// destination: the raw synthetic IPv6 address, and the hyphenated MagicDNS name.
type via6Target struct {
	viaIP   string // e.g. "fd7a:115c:a1e0:b1a::7:a01:5"
	viaFQDN string // e.g. "10-1-0-5-via-7.<tailnet>.ts.net"
}

// setup4via6Backend deploys an nginx backend behind an IPv4-only ClusterIP
// Service, creates a Connector subnet router advertising the 4via6 route that
// covers that ClusterIP, waits for the route to be advertised on the tailnet,
// and returns the two forms a 4via6 egress target can take.
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

	// Hyphenated MagicDNS name of the form <a-b-c-d>-via-<siteID>.<tailnet>.
	hyphenatedIP := strings.ReplaceAll(ip.String(), ".", "-")
	viaFQDN := fmt.Sprintf("%s-via-%d.%s", hyphenatedIP, via6SiteID, tailnetDomain(t, tnClient))

	return via6Target{
		viaIP:   via.Addr().String(),
		viaFQDN: viaFQDN,
	}
}

// acceptRoutesProxyClass creates a ProxyClass that enables AcceptRoutes so that
// egress proxies install the Connector's advertised 4via6 route, and returns its
// name. It mirrors the StatefulSet/ACME configuration of the harness's "default"
// ProxyClass (see applyDefaultProxyClass in setup.go).
func acceptRoutesProxyClass(t *testing.T) string {
	t.Helper()

	var env []tsapi.Env
	if *fDevcontrol {
		env = []tsapi.Env{{
			Name:  "TS_DEBUG_ACME_DIRECTORY_URL",
			Value: "https://pebble:14000/dir",
		}}
	}
	pc := &tsapi.ProxyClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: generateName("accept-routes"),
		},
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

	if err := tstest.WaitFor(time.Minute, func() error {
		got := &tsapi.ProxyClass{}
		if err := kubeClient.Get(t.Context(), client.ObjectKey{Name: pc.Name}, got); err != nil {
			return err
		}
		if !kube.ProxyClassIsReady(got) {
			return fmt.Errorf("ProxyClass %s not ready yet", pc.Name)
		}
		return nil
	}); err != nil {
		t.Fatalf("waiting for ProxyClass %s to become ready: %v", pc.Name, err)
	}
	return pc.Name
}

// tailnetDomain returns the tailnet's MagicDNS domain (the DNSName suffix after
// the node name) for the given tailnet client, e.g. "example.ts.net".
func tailnetDomain(t *testing.T, cl *tsnet.Server) string {
	t.Helper()
	lc, err := cl.LocalClient()
	if err != nil {
		t.Fatalf("getting local client: %v", err)
	}
	status, err := lc.Status(t.Context())
	if err != nil {
		t.Fatalf("getting tailnet status: %v", err)
	}
	_, domain, ok := strings.Cut(strings.TrimSuffix(status.Self.DNSName, "."), ".")
	if !ok {
		t.Fatalf("unexpected DNSName format %q", status.Self.DNSName)
	}
	return domain
}
