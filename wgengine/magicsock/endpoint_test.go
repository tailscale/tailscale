// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
	"tailscale.com/util/ringlog"
)

func TestProbeUDPLifetimeConfig_Equals(t *testing.T) {
	tests := []struct {
		name string
		a    *ProbeUDPLifetimeConfig
		b    *ProbeUDPLifetimeConfig
		want bool
	}{
		{
			"both sides nil",
			nil,
			nil,
			true,
		},
		{
			"equal pointers",
			defaultProbeUDPLifetimeConfig,
			defaultProbeUDPLifetimeConfig,
			true,
		},
		{
			"a nil",
			nil,
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"b nil",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			nil,
			false,
		},
		{
			"Cliffs unequal",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 2},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"CycleCanStartEvery unequal",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour,
			},
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second},
				CycleCanStartEvery: time.Hour * 2,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.Equals(tt.b); got != tt.want {
				t.Errorf("Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestProbeUDPLifetimeConfig_Valid(t *testing.T) {
	tests := []struct {
		name string
		p    *ProbeUDPLifetimeConfig
		want bool
	}{
		{
			"default config valid",
			defaultProbeUDPLifetimeConfig,
			true,
		},
		{
			"no cliffs",
			&ProbeUDPLifetimeConfig{
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"zero CycleCanStartEvery",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 10},
				CycleCanStartEvery: 0,
			},
			false,
		},
		{
			"cliff too small",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{min(udpLifetimeProbeCliffSlack*2, heartbeatInterval)},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"duplicate Cliffs values",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 2, time.Second * 2},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
		{
			"Cliffs not ascending",
			&ProbeUDPLifetimeConfig{
				Cliffs:             []time.Duration{time.Second * 2, time.Second * 1},
				CycleCanStartEvery: time.Hour,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.Valid(); got != tt.want {
				t.Errorf("Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_endpoint_maybeProbeUDPLifetimeLocked(t *testing.T) {
	var lowerPriv, higherPriv key.DiscoPrivate
	var lower, higher key.DiscoPublic
	privA := key.NewDisco()
	privB := key.NewDisco()
	a := privA.Public()
	b := privB.Public()
	if a.String() < b.String() {
		lower = a
		higher = b
		lowerPriv = privA
		higherPriv = privB
	} else {
		lower = b
		higher = a
		lowerPriv = privB
		higherPriv = privA
	}
	addr := addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("1.1.1.1:1")}}
	newProbeUDPLifetime := func() *probeUDPLifetime {
		return &probeUDPLifetime{
			config: *defaultProbeUDPLifetimeConfig,
		}
	}

	tests := []struct {
		name                     string
		localDisco               key.DiscoPublic
		remoteDisco              *key.DiscoPublic
		probeUDPLifetimeFn       func() *probeUDPLifetime
		bestAddr                 addrQuality
		wantAfterInactivityForFn func(*probeUDPLifetime) time.Duration
		wantMaybe                bool
	}{
		{
			name:        "nil-probeUDPLifetime",
			localDisco:  higher,
			remoteDisco: &lower,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				return nil
			},
			bestAddr: addr,
		},
		{
			name:               "local-higher-disco-key",
			localDisco:         higher,
			remoteDisco:        &lower,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addr,
		},
		{
			name:               "remote-no-disco-key",
			localDisco:         higher,
			remoteDisco:        nil,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addr,
		},
		{
			name:               "invalid-bestAddr",
			localDisco:         lower,
			remoteDisco:        &higher,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addrQuality{},
		},
		{
			name:        "cycle-started-too-recently",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = false
				lt.cycleStartedAt = time.Now()
				return lt
			},
			bestAddr: addr,
		},
		{
			name:        "maybe-cliff-0-cycle-not-active",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = false
				lt.cycleStartedAt = time.Now().Add(-lt.config.CycleCanStartEvery).Add(-time.Second)
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[0] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
		{
			name:        "maybe-cliff-0",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = true
				lt.currentCliff = 0
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[0] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
		{
			name:        "maybe-cliff-1",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = true
				lt.currentCliff = 1
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[1] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
		{
			name:        "maybe-cliff-2",
			localDisco:  lower,
			remoteDisco: &higher,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				lt := newProbeUDPLifetime()
				lt.cycleActive = true
				lt.currentCliff = 2
				return lt
			},
			bestAddr: addr,
			wantAfterInactivityForFn: func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[2] - udpLifetimeProbeCliffSlack
			},
			wantMaybe: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Conn{}
			if tt.localDisco.IsZero() {
				c.discoAtomic.Set(key.NewDisco())
			} else if tt.localDisco.Compare(lower) == 0 {
				c.discoAtomic.Set(lowerPriv)
			} else if tt.localDisco.Compare(higher) == 0 {
				c.discoAtomic.Set(higherPriv)
			} else {
				t.Fatalf("unexpected localDisco value")
			}
			de := &endpoint{
				c:        c,
				bestAddr: tt.bestAddr,
			}
			if tt.remoteDisco != nil {
				remote := &endpointDisco{
					key: *tt.remoteDisco,
				}
				de.disco.Store(remote)
			}
			p := tt.probeUDPLifetimeFn()
			de.probeUDPLifetime = p
			gotAfterInactivityFor, gotMaybe := de.maybeProbeUDPLifetimeLocked()
			var wantAfterInactivityFor time.Duration
			if tt.wantAfterInactivityForFn != nil {
				wantAfterInactivityFor = tt.wantAfterInactivityForFn(p)
			}
			if gotAfterInactivityFor != wantAfterInactivityFor {
				t.Errorf("maybeProbeUDPLifetimeLocked() gotAfterInactivityFor = %v, want %v", gotAfterInactivityFor, wantAfterInactivityFor)
			}
			if gotMaybe != tt.wantMaybe {
				t.Errorf("maybeProbeUDPLifetimeLocked() gotMaybe = %v, want %v", gotMaybe, tt.wantMaybe)
			}
		})
	}
}

func Test_epAddr_isDirectUDP(t *testing.T) {
	vni := packet.VirtualNetworkID{}
	vni.Set(7)
	tests := []struct {
		name string
		ap   netip.AddrPort
		vni  packet.VirtualNetworkID
		want bool
	}{
		{
			name: "true",
			ap:   netip.MustParseAddrPort("192.0.2.1:7"),
			vni:  packet.VirtualNetworkID{},
			want: true,
		},
		{
			name: "false-derp-magic-addr",
			ap:   netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 0),
			vni:  packet.VirtualNetworkID{},
			want: false,
		},
		{
			name: "false-vni-set",
			ap:   netip.MustParseAddrPort("192.0.2.1:7"),
			vni:  vni,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := epAddr{
				ap:  tt.ap,
				vni: tt.vni,
			}
			if got := e.isDirect(); got != tt.want {
				t.Errorf("isDirect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_endpoint_udpRelayEndpointReady(t *testing.T) {
	directAddrQuality := addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}}
	peerRelayAddrQuality := addrQuality{epAddr: epAddr{ap: netip.MustParseAddrPort("192.0.2.2:77")}, latency: time.Second}
	peerRelayAddrQuality.vni.Set(1)
	peerRelayAddrQualityHigherLatencySameServer := addrQuality{
		epAddr:  epAddr{ap: netip.MustParseAddrPort("192.0.2.3:77"), vni: peerRelayAddrQuality.vni},
		latency: peerRelayAddrQuality.latency * 10,
	}
	peerRelayAddrQualityHigherLatencyDiffServer := addrQuality{
		epAddr:           epAddr{ap: netip.MustParseAddrPort("192.0.2.3:77"), vni: peerRelayAddrQuality.vni},
		latency:          peerRelayAddrQuality.latency * 10,
		relayServerDisco: key.NewDisco().Public(),
	}
	peerRelayAddrQualityLowerLatencyDiffServer := addrQuality{
		epAddr:           epAddr{ap: netip.MustParseAddrPort("192.0.2.4:77"), vni: peerRelayAddrQuality.vni},
		latency:          peerRelayAddrQuality.latency / 10,
		relayServerDisco: key.NewDisco().Public(),
	}
	peerRelayAddrQualityEqualLatencyDiffServer := addrQuality{
		epAddr:           epAddr{ap: netip.MustParseAddrPort("192.0.2.4:77"), vni: peerRelayAddrQuality.vni},
		latency:          peerRelayAddrQuality.latency,
		relayServerDisco: key.NewDisco().Public(),
	}
	tests := []struct {
		name               string
		curBestAddr        addrQuality
		trustBestAddrUntil mono.Time
		maybeBest          addrQuality
		wantBestAddr       addrQuality
	}{
		{
			name:               "bestAddr-trusted-direct",
			curBestAddr:        directAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQuality,
			wantBestAddr:       directAddrQuality,
		},
		{
			name:               "bestAddr-untrusted-direct",
			curBestAddr:        directAddrQuality,
			trustBestAddrUntil: mono.Now().Add(-1 * time.Hour),
			maybeBest:          peerRelayAddrQuality,
			wantBestAddr:       peerRelayAddrQuality,
		},
		{
			name:               "maybeBest-same-relay-higher-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityHigherLatencySameServer,
			wantBestAddr:       peerRelayAddrQualityHigherLatencySameServer,
		},
		{
			name:               "maybeBest-diff-relay-higher-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityHigherLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQuality,
		},
		{
			name:               "maybeBest-diff-relay-lower-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityLowerLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQualityLowerLatencyDiffServer,
		},
		{
			name:               "maybeBest-diff-relay-equal-latency-trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityEqualLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQuality,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{
				c:                  &Conn{logf: func(msg string, args ...any) { return }},
				bestAddr:           tt.curBestAddr,
				trustBestAddrUntil: tt.trustBestAddrUntil,
			}
			de.udpRelayEndpointReady(tt.maybeBest)
			if de.bestAddr != tt.wantBestAddr {
				t.Errorf("de.bestAddr = %v, want %v", de.bestAddr, tt.wantBestAddr)
			}
		})
	}
}

func Test_endpoint_discoPingTimeout(t *testing.T) {
	expired := -1 * time.Hour
	valid := 1 * time.Hour
	directAddrA := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	relayAddrA := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:77")}
	relayAddrA.vni.Set(1)
	directAddrB := epAddr{ap: netip.MustParseAddrPort("192.0.2.3:7")}
	relayAddrB := epAddr{ap: netip.MustParseAddrPort("192.0.2.4:77")}
	relayAddrB.vni.Set(1)

	for _, tc := range []struct {
		name                string
		bestAddr            addrQuality
		trustBestAddrUntil  time.Duration
		pingTo              epAddr
		wantBestAddrCleared bool
	}{
		{
			name:                "relay-path-trust-expired",
			bestAddr:            addrQuality{epAddr: relayAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              relayAddrA,
			wantBestAddrCleared: true,
		},
		{
			name:                "direct-udp-path-trust-expired",
			bestAddr:            addrQuality{epAddr: directAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              directAddrA,
			wantBestAddrCleared: true,
		},
		{
			name:                "direct-udp-path-trust-valid",
			bestAddr:            addrQuality{epAddr: directAddrA},
			trustBestAddrUntil:  valid,
			pingTo:              directAddrA,
			wantBestAddrCleared: false,
		},
		{
			name:                "relay-path-trust-valid",
			bestAddr:            addrQuality{epAddr: relayAddrA},
			trustBestAddrUntil:  valid,
			pingTo:              relayAddrA,
			wantBestAddrCleared: false,
		},
		{
			name:                "ping-to-different-direct-addr-trust-expired",
			bestAddr:            addrQuality{epAddr: directAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              directAddrB,
			wantBestAddrCleared: false,
		},
		{
			name:                "ping-to-different-relay-addr-trust-expired",
			bestAddr:            addrQuality{epAddr: relayAddrA},
			trustBestAddrUntil:  expired,
			pingTo:              relayAddrB,
			wantBestAddrCleared: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := mono.Now() // synctest to match this to the internal 'now'
				c := &Conn{
					logf: func(msg string, args ...any) {},
				}
				c.discoAtomic.Set(key.NewDisco())
				de := &endpoint{
					c:                  c,
					bestAddr:           tc.bestAddr,
					trustBestAddrUntil: now.Add(tc.trustBestAddrUntil),
					sentPing:           make(map[stun.TxID]sentPing),
				}
				txid := stun.NewTxID()
				timer := time.NewTimer(time.Hour)
				timer.Stop()
				de.sentPing[txid] = sentPing{
					to:      tc.pingTo,
					at:      now.Add(-100 * time.Millisecond),
					timer:   timer,
					purpose: pingDiscovery,
				}

				de.discoPingTimeout(txid)
				if tc.wantBestAddrCleared {
					if de.bestAddr.ap.IsValid() {
						t.Errorf("expected bestAddr to be cleared, but bestAddr.ap is valid: %v", de.bestAddr.ap)
					}
					if de.trustBestAddrUntil != 0 {
						t.Errorf("expected trustBestAddrUntil to be cleared, but got: %v", de.trustBestAddrUntil)
					}
				} else {
					if de.bestAddr != tc.bestAddr {
						t.Errorf("expected bestAddr to be unchanged, got: %v, want: %v", de.bestAddr, tc.bestAddr)
					}
				}
				if _, ok := de.sentPing[txid]; ok {
					t.Errorf("expected sentPing[txid] to be removed, but it still exists")
				}
			})
		})
	}
}

func Test_endpoint_handlePongConnLocked(t *testing.T) {
	goodLatency := 50 * time.Millisecond
	badLatency := 100 * time.Millisecond
	expired := -1 * time.Hour
	valid := 1 * time.Hour
	directAddrA := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}
	directAddrB := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:8")}
	derpAddr := epAddr{ap: netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 0)}

	for _, tc := range []struct {
		name               string
		bestAddr           addrQuality
		trustBestAddrUntil time.Duration
		pongFrom           epAddr
		pongLatency        time.Duration
		wantBestAddr       epAddr
	}{
		{
			name:               "better-latency-trust-valid",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: valid,
			pongFrom:           directAddrB,
			pongLatency:        goodLatency,
			wantBestAddr:       directAddrB,
		},
		{
			name:               "worse-latency-trust-valid",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: goodLatency},
			trustBestAddrUntil: valid,
			pongFrom:           directAddrB,
			pongLatency:        badLatency,
			wantBestAddr:       directAddrA,
		},
		{
			name:               "worse-latency-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: goodLatency},
			trustBestAddrUntil: expired,
			pongFrom:           directAddrB,
			pongLatency:        badLatency,
			wantBestAddr:       directAddrB,
		},
		{
			name:               "same-path-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: expired,
			pongFrom:           directAddrA,
			pongLatency:        goodLatency, // updated latency
			wantBestAddr:       directAddrA,
		},
		{
			name:               "derp-pong-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: expired,
			pongFrom:           derpAddr,
			pongLatency:        goodLatency,
			wantBestAddr:       directAddrA,
		},
		{
			name:               "better-latency-trust-expired",
			bestAddr:           addrQuality{epAddr: directAddrA, latency: badLatency},
			trustBestAddrUntil: expired,
			pongFrom:           directAddrB,
			pongLatency:        goodLatency,
			wantBestAddr:       directAddrB,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := mono.Now() // synctest to match this to the internal 'now'
				pm := newPeerMap()
				c := &Conn{
					logf:    func(msg string, args ...any) {},
					peerMap: pm,
				}
				c.discoAtomic.Set(key.NewDisco())
				de := &endpoint{
					c:                  c,
					bestAddr:           tc.bestAddr,
					bestAddrAt:         now.Add(-5 * time.Minute),
					trustBestAddrUntil: now.Add(tc.trustBestAddrUntil),
					sentPing:           make(map[stun.TxID]sentPing),
					endpointState:      make(map[netip.AddrPort]*endpointState),
					debugUpdates:       ringlog.New[EndpointChange](10),
				}
				txid := stun.NewTxID()
				pong := &disco.Pong{
					TxID: txid,
					Src:  tc.pongFrom.ap,
				}
				timer := time.NewTimer(time.Hour)
				timer.Stop()
				de.sentPing[txid] = sentPing{
					to:      tc.pongFrom,
					at:      now.Add(-tc.pongLatency),
					timer:   timer,
					purpose: pingDiscovery,
				}
				if tc.pongFrom.ap.Addr() != tailcfg.DerpMagicIPAddr && !tc.pongFrom.vni.IsSet() {
					de.endpointState[tc.pongFrom.ap] = &endpointState{}
				}
				di := &discoInfo{
					discoKey:   key.NewDisco().Public(),
					discoShort: "test",
				}

				knownTxID := de.handlePongConnLocked(pong, di, tc.pongFrom)
				if !knownTxID {
					t.Errorf("expected knownTxID to be true, got false")
				}
				if de.bestAddr.epAddr != tc.wantBestAddr {
					t.Errorf("expected bestAddr.epAddr to be %v, got: %v", tc.wantBestAddr, de.bestAddr.epAddr)
				}
				if tc.pongFrom == tc.bestAddr.epAddr && de.bestAddr.latency-tc.pongLatency > 0 {
					t.Errorf("expected latency to be  %v, got: %v", tc.pongLatency, de.bestAddr.latency)
				}
				if tc.pongFrom != derpAddr && de.trustBestAddrUntil.Before(now) {
					t.Errorf("expected trustBestAddrUntil to be refreshed, but it's in the past: %v", de.trustBestAddrUntil)
				}
				if _, ok := de.sentPing[txid]; ok {
					t.Errorf("expected sentPing[txid] to be removed, but it still exists")
				}
			})
		})
	}
}
