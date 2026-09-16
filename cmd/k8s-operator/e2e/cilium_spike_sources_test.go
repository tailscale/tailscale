// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"

	"tailscale.com/kube/kubetypes"
	"tailscale.com/kube/routesources"
)

// kindServiceSubnet is kind's default IPv4 Service subnet.
const kindServiceSubnet = "10.96.0.0/16"

// TestCiliumSpikeSources validates the enforcement of route sources
// (RouteAcceptor spec.sources) under Cilium's eBPF host routing with a
// Cilium-managed tailscale0 and under legacy host routing, without the
// operator: it writes the documents the operator would write into the route
// acceptor's state Secret and checks which Pods reach the subnet.
//
// Run with: go test -count=1 -v -timeout 60m ./cmd/k8s-operator/e2e/ --build --cluster --cni=cilium --cilium-spike -run TestCiliumSpikeSources
func TestCiliumSpikeSources(t *testing.T) {
	if !ciliumSpike {
		t.Skip("TestCiliumSpikeSources requires --cilium-spike")
	}
	ctx := t.Context()

	spikeDeploy(t, true)

	url := fmt.Sprintf("http://%s/healthz", testSubnetIP)
	largeURL := fmt.Sprintf("http://%s:8080/large.bin", testSubnetIP)

	type check struct {
		name string
		// selected lists the probe Pod in the document, with routes (nil: every route).
		selected bool
		routes   []netip.Prefix
		// wantReachable is whether the probe Pod is expected to reach the subnet.
		wantReachable bool
		// largeDownload also checks that a 1 MiB download completes.
		largeDownload bool
	}
	checks := []check{
		{name: "selected-all-routes", selected: true, wantReachable: true, largeDownload: true},
		{name: "unselected", wantReachable: false},
		{name: "selected-other-routes", selected: true, routes: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}, wantReachable: false},
		{name: "selected-subnet-route", selected: true, routes: []netip.Prefix{netip.MustParsePrefix(testSubnet)}, wantReachable: true},
	}
	configs := []struct {
		name string
		sets []string
	}{
		{name: "ebpf-host-routing-managed-tailscale0"},
		{name: "legacy-host-routing", sets: []string{"bpf.hostLegacyRouting=true"}},
	}
	for _, cfg := range configs {
		t.Run(cfg.name, func(t *testing.T) {
			if err := ciliumHelm.apply(ctx, kzap.NewRaw().Sugar(), cfg.sets); err != nil {
				t.Fatalf("reconfiguring Cilium: %v", err)
			}
			// Give the agents a moment to regenerate their programs after the rollout.
			time.Sleep(15 * time.Second)

			for _, c := range checks {
				t.Run(c.name, func(t *testing.T) {
					opts := curlPodOptions{}
					if c.selected {
						// The probe Pod's address is only known once it runs; it retries until the device has
						// picked up the document.
						opts.onPodIP = func(ip string) {
							writeSpikeRouteSources(t, []routesources.Group{spikeGroup(t, c.routes, ip)})
						}
					} else {
						writeSpikeRouteSources(t, nil)
					}
					attempts := 40
					if !c.wantReachable {
						attempts = 15
					}
					reachable := targetIsReachableWith(t, url, attempts, opts)
					if reachable != c.wantReachable {
						t.Errorf("reachable = %v, want %v", reachable, c.wantReachable)
					}
					if c.largeDownload && reachable && !targetDownloadsBytesWith(t, largeURL, largeFileSize, 20, opts) {
						t.Errorf("a %d-byte download from the subnet did not complete", largeFileSize)
					}
				})
			}
		})
	}
}

// spikeGroup returns a document group listing ip with the given routes (nil: every route).
func spikeGroup(t *testing.T, routes []netip.Prefix, ip string) routesources.Group {
	t.Helper()
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("parsing probe Pod address %q: %v", ip, err)
	}
	g := routesources.Group{IPs: []netip.Addr{addr}}
	if routes != nil {
		g.Routes = routes
		if g.Table, err = routesources.TableFor(routes, nil); err != nil {
			t.Fatal(err)
		}
	}
	return g
}

// writeSpikeRouteSources writes the route sources document with the given groups into the state Secret of every
// node's device, as the operator would.
func writeSpikeRouteSources(t *testing.T, groups []routesources.Group) {
	t.Helper()
	ctx := t.Context()
	doc := &routesources.Document{
		Version:      routesources.Version,
		ClusterCIDRs: []netip.Prefix{netip.MustParsePrefix(kindPodSubnet), netip.MustParsePrefix(kindServiceSubnet)},
		Groups:       groups,
	}
	b, err := doc.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	patch, err := json.Marshal(map[string]any{"data": map[string][]byte{kubetypes.KeyRouteSources: b}})
	if err != nil {
		t.Fatal(err)
	}
	var nodes corev1.NodeList
	if err := kubeClient.List(ctx, &nodes); err != nil {
		t.Fatalf("listing nodes: %v", err)
	}
	for _, n := range nodes.Items {
		s := &corev1.Secret{ObjectMeta: objectMeta(ns, spikeAcceptorName+"-"+n.Name)}
		if err := kubeClient.Patch(ctx, s, client.RawPatch(types.MergePatchType, patch)); err != nil {
			t.Fatalf("writing route sources for %s: %v", n.Name, err)
		}
	}
	t.Logf("wrote route sources with %d group(s)", len(groups))
}
