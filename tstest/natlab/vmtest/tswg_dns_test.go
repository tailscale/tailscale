// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/dnstype"
)

// TestTSWGTailscaledMagicDNS checks MagicDNS in kernel mode: queries to
// 100.100.100.100 and fd7a:115c:a1e0::53, over UDP and TCP, from the
// node's own network stack, answered by tailscaled. In kernel mode the
// tswg device doesn't hand tailscaled packets, so the router sends the
// routes to the service IPs to a separate TUN device, from which netstack
// answers them as in TUN mode.
func TestTSWGTailscaledMagicDNS(t *testing.T) {
	f := newTSWGTailscaledOpts(t, vnet.EasyNAT, tswgTailscaledOpts{
		vmOpts: []vmtest.EnvOption{vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
			Proxied: true,
			Domains: []string{"tailnet.test", "record"},
			Routes: map[string][]*dnstype.Resolver{
				"tailnet.test": nil,
				"record":       nil,
			},
			ExtraRecords: []tailcfg.DNSRecord{
				{Name: "extratest.record", Type: "A", Value: "1.2.3.4"},
			},
		})},
	})
	n1, n2 := f.nodes[0], f.nodes[1]
	peerName := strings.TrimSuffix(f.env.Status(n2).Self.DNSName, ".")
	peerIP := f.ip(n2).String()

	for _, server := range []string{tsaddr.TailscaleServiceIP().String(), tsaddr.TailscaleServiceIPv6().String()} {
		for _, network := range []string{"udp", "tcp"} {
			for name, want := range map[string]string{
				"extratest.record": "1.2.3.4",
				peerName:           peerIP,
			} {
				if err := tstest.WaitFor(20*time.Second, func() error {
					got, err := ttaErr(n1, "GET", "/dns-lookup?"+url.Values{
						"server": {server}, "name": {name}, "net": {network},
					}.Encode(), nil)
					if err != nil {
						return err
					}
					if !strings.Contains(got, want) {
						return fmt.Errorf("got %q, want %q", strings.TrimSpace(got), want)
					}
					return nil
				}); err != nil {
					t.Errorf("[%s] looking up %s at %s over %s: %v", n1.Name(), name, server, network, err)
				} else {
					t.Logf("[%s] %s at %s over %s: %s", n1.Name(), name, server, network, want)
				}
			}
		}
	}

	// And the tunnel to the peer still works.
	f.env.LANPing(n1, f.ip(n2))
}
