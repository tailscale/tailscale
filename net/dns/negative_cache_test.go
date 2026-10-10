// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"net/netip"
	"runtime"
	"testing"

	"tailscale.com/health"
	"tailscale.com/internal/dnstest"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/netmon"
	"tailscale.com/net/tsdial"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/eventbus/eventbustest"
)

// TestNegativeCacheFlushHook checks hook invocation, removal, and suppression
// after a global flush, using the implementation selected at build time.
func TestNegativeCacheFlushHook(t *testing.T) {
	for _, goos := range []string{"darwin", "ios", "linux", "windows"} {
		t.Run(goos, func(t *testing.T) {
			for _, tt := range []struct {
				name                             string
				resolve, globalFlush, removeHook bool
				want                             int
			}{
				{name: "still_missing"},
				{name: "became_resolvable", resolve: true, want: 1},
				{name: "global_flush_clears_history", resolve: true, globalFlush: true},
				{name: "removed_hook", resolve: true, removeHook: true},
			} {
				t.Run(tt.name, func(t *testing.T) {
					bus := eventbustest.NewBus(t)
					dialer := tsdial.NewDialer(netmon.NewStatic())
					dialer.SetBus(bus)
					m := NewManager(t.Logf, &fakeOSConfigurator{}, health.NewTracker(bus), dialer, nil, nil, goos, bus)
					defer m.Down()
					flushed := 0
					m.SetCacheFlushHook(func() { flushed++ })
					cfg := resolver.Config{LocalDomains: []dnsname.FQDN{"test.net."}}
					if err := m.Resolver().SetConfig(cfg); err != nil {
						t.Fatal(err)
					}
					dnstest.RequireNXDOMAIN(t, m.Query, "server.test.net.")
					if tt.globalFlush {
						if err := m.FlushCaches(); err != nil {
							t.Fatal(err)
						}
						if flushed != tt.want {
							t.Fatalf("global flush calls = %d, want %d", flushed, tt.want)
						}
					}
					if tt.removeHook {
						m.SetCacheFlushHook(nil)
						dnstest.RequireNXDOMAIN(t, m.Query, "server.test.net.")
					}
					if tt.resolve {
						cfg.Hosts = map[dnsname.FQDN][]netip.Addr{"server.test.net.": {netip.MustParseAddr("100.64.0.2")}}
						if err := m.Resolver().SetConfig(cfg); err != nil {
							t.Fatal(err)
						}
					}
					want := tt.want
					if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
						// The compiled stub never requests a flush after a peer update.
						want = 0
					}
					for check := range 2 {
						m.CheckCachedDNS()
						if flushed != want {
							t.Fatalf("check %d: flushes = %d, want %d", check, flushed, want)
						}
					}
				})
			}
		})
	}
}
