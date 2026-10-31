// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netcheckhook

import (
	"context"
	"sync/atomic"
	"testing"

	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
)

func emptyDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
}

func TestStartCaptivePortalDetectionDisabled(t *testing.T) {
	var disabled atomic.Bool
	c := &netcheck.Client{
		NetMon:                        netmon.NewStatic(),
		DisableCaptivePortalDetection: disabled.Load,
	}

	// The callback must be consulted when detection would start, not copied
	// when the client is constructed.
	disabled.Store(true)

	done, stop := startCaptivePortalDetection(context.Background(), c, emptyDERPMap(), 0, func(bool) {
		t.Error("captive portal detection ran despite being disabled")
	})
	defer stop()

	select {
	case <-done:
	default:
		t.Fatal("done channel is not closed for disabled captive portal detection")
	}

	// The same client must resume normal detection after the live knob changes.
	disabled.Store(false)
	done, stop = startCaptivePortalDetection(context.Background(), c, emptyDERPMap(), 0, func(bool) {})
	select {
	case <-done:
		t.Fatal("detection was skipped after being re-enabled")
	default:
	}
	stop()
	<-done
}

func TestStartCaptivePortalDetectionEnabledByDefault(t *testing.T) {
	for _, test := range []struct {
		name string
		c    *netcheck.Client
	}{
		{"nil callback", &netcheck.Client{NetMon: netmon.NewStatic()}},
		{"false callback", &netcheck.Client{
			NetMon:                        netmon.NewStatic(),
			DisableCaptivePortalDetection: func() bool { return false },
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			done, stop := startCaptivePortalDetection(context.Background(), test.c, emptyDERPMap(), 0, func(bool) {})
			select {
			case <-done:
				t.Fatal("detection was skipped while enabled")
			default:
			}
			stop()
			<-done
		})
	}
}
