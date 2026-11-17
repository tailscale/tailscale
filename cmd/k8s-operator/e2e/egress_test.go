// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"tailscale.com/client/tailscale/v2"
	kube "tailscale.com/k8s-operator"
	tsapi "tailscale.com/k8s-operator/apis/v1alpha1"
	"tailscale.com/tstest"
)

const egressPort = 80

// tailnetTarget holds the FQDN, IPv4, and IPv6 addresses of a tailnet node
// running an HTTP server, for use as an egress target in tests.
type tailnetTarget struct {
	fqdn, ipv4, ipv6 string
}

// See [TestMain] for test requirements.
func TestEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestEgress requires a working tailnet client")
	}
	t.Parallel()

	target := startEgressTarget(t, tsClient)

	t.Run("IPv4", func(t *testing.T) {
		if !clusterIPv4Support {
			t.Skip("cluster does not support IPv4")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip": target.ipv4,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})

	t.Run("IPv6", func(t *testing.T) {
		if !clusterIPv6Support {
			t.Skip("cluster does not support IPv6")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip": target.ipv6,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})

	t.Run("FQDN", func(t *testing.T) {
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-fqdn": target.fqdn,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, kube.SvcIsReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})
}

// See [TestMain] for test requirements.
func TestHAEgress(t *testing.T) {
	if tnClient == nil {
		t.Skip("TestHAEgress requires a working tailnet client")
	}
	t.Parallel()

	target := startEgressTarget(t, tsClient)

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
			"tailscale.com/tailnet-ip":  target.ipv4,
			"tailscale.com/proxy-group": pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})

	t.Run("IPv6", func(t *testing.T) {
		if !clusterIPv6Support {
			t.Skip("cluster does not support IPv6")
		}
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-ip":  target.ipv6,
			"tailscale.com/proxy-group": pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		requireTargetIsReachable(t, egressURL(svc.Name))
	})

	t.Run("FQDN", func(t *testing.T) {
		svc := egressService(generateName("test-egress"), map[string]string{
			"tailscale.com/tailnet-fqdn": target.fqdn,
			"tailscale.com/proxy-group":  pg.Name,
		})
		createAndCleanup(t, kubeClient, svc)
		waitForEgress(t, svc.Name, pgEgressReady)
		// Test the egress target is reachable via both its in-cluster Service name, and its Magic DNS name.
		requireTargetIsReachable(t, egressURL(svc.Name))
		requireTargetIsReachable(t, fmt.Sprintf("http://%s:%d", target.fqdn, egressPort))
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

	target := startEgressTarget(t, secondTSClient)
	svc := egressService(generateName("test-egress"), map[string]string{
		"tailscale.com/tailnet-fqdn": target.fqdn,
		"tailscale.com/proxy-group":  pg.Name,
	})
	createAndCleanup(t, kubeClient, svc)
	waitForEgress(t, svc.Name, pgEgressReady)
	// Test the egress target is reachable via both its in-cluster Service name, and its Magic DNS name.
	requireTargetIsReachable(t, egressURL(svc.Name))
	requireTargetIsReachable(t, fmt.Sprintf("http://%s:%d", target.fqdn, egressPort))
}

func startEgressTarget(t *testing.T, cl *tailscale.Client) tailnetTarget {
	t.Helper()
	srv := newTailnetNode(t, cl, generateName("test-egress-target"))

	ln, err := srv.Listen("tcp", fmt.Sprintf(":%d", egressPort))
	if err != nil {
		t.Fatalf("listening on egress target: %v", err)
	}
	go func() {
		if err := http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("egress target HTTP server exited: %v", err)
		}
	}()

	lc, err := srv.LocalClient()
	if err != nil {
		t.Fatalf("getting egress target local client: %v", err)
	}
	status, err := lc.StatusWithoutPeers(t.Context())
	if err != nil {
		t.Fatalf("getting egress target status: %v", err)
	}
	target := tailnetTarget{fqdn: strings.TrimSuffix(status.Self.DNSName, ".")}
	for _, ip := range status.TailscaleIPs {
		if ip.Is4() {
			target.ipv4 = ip.String()
		} else {
			target.ipv6 = ip.String()
		}
	}
	return target
}

func egressService(name string, annotations map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			ExternalName: "placeholder",
			Type:         corev1.ServiceTypeExternalName,
			Ports: []corev1.ServicePort{
				{
					Name:     "http",
					Protocol: corev1.ProtocolTCP,
					Port:     egressPort,
				},
			},
		},
	}
}

func pgEgressReady(svc *corev1.Service) bool {
	cond := kube.GetServiceCondition(svc, tsapi.EgressSvcReady)
	return cond != nil && cond.Status == metav1.ConditionTrue
}

func egressURL(svcName string) string {
	return fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svcName, ns, egressPort)
}

func waitForEgress(t *testing.T, svcName string, ready func(*corev1.Service) bool) {
	t.Helper()
	if err := tstest.WaitFor(5*time.Minute, func() error {
		svc := &corev1.Service{ObjectMeta: objectMeta(ns, svcName)}
		if err := get(t.Context(), kubeClient, svc); err != nil {
			return err
		}
		if ready(svc) {
			t.Logf("Service %s is ready", svcName)
			return nil
		}
		return fmt.Errorf("Service %s is not ready yet", svcName)
	}); err != nil {
		t.Fatalf("error waiting for Service %s to become ready: %v", svcName, err)
	}
}
