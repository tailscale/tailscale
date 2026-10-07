// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package ipnlocal

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/types/appctype"
	"tailscale.com/util/eventbus/eventbustest"
)

func TestAppConnectorRouteRetentionKnob(t *testing.T) {
	envknob.SetenvForTest(t, "TS_DEBUG_APPC_ROUTE_RETENTION", "24h")
	bus := eventbustest.NewBus(t)
	w := eventbustest.NewWatcher(t, bus)
	addr := netip.MustParseAddr("192.0.2.1")
	ri := &appctype.RouteInfo{Domains: map[string][]netip.Addr{"example.com": {addr}}}
	before := time.Now()
	a := newAppConnector(t.Logf, bus, ri, true)
	t.Cleanup(a.Close)
	if err := eventbustest.Expect(w, func(ri appctype.RouteInfo) error {
		deadline := ri.DomainExpiry["example.com"][addr]
		if deadline.Before(before.Add(24 * time.Hour)) {
			t.Errorf("legacy route deadline %v does not include configured retention", deadline)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
