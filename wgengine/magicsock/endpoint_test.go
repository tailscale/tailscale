// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"fmt"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/disco"
	"tailscale.com/envknob"
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
			c := &Conn{logf: func(msg string, args ...any) {}}
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
				de.updateDiscoKey(*tt.remoteDisco)
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

func Test_endpoint_sendDiscoPingsLocked_neverDirectUDP(t *testing.T) {
	directAddr := netip.MustParseAddrPort("192.0.2.1:7")
	for _, neverDirectUDP := range []bool{false, true} {
		t.Run(fmt.Sprintf("neverDirectUDP=%v", neverDirectUDP), func(t *testing.T) {
			prev := envknob.String("TS_DEBUG_NEVER_DIRECT_UDP")
			if neverDirectUDP {
				envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "true")
			} else {
				envknob.SetenvForTest(t, "TS_DEBUG_NEVER_DIRECT_UDP", "")
			}
			t.Cleanup(func() { envknob.Setenv("TS_DEBUG_NEVER_DIRECT_UDP", prev) })
			now := mono.Now()
			c := &Conn{
				logf: func(msg string, args ...any) {},
			}
			c.discoAtomic.Set(key.NewDisco())
			de := &endpoint{
				c:             c,
				sentPing:      make(map[stun.TxID]sentPing),
				endpointState: make(map[netip.AddrPort]*endpointState),
			}
			de.updateDiscoKey(key.NewDisco().Public())
			de.endpointState[directAddr] = &endpointState{}
			de.sendDiscoPingsLocked(now, true)

			wantPing := !neverDirectUDP
			if gotPing := de.lastFullPing == now; gotPing != wantPing {
				t.Errorf("lastFullPing set = %v, want %v", gotPing, wantPing)
			}
			if gotPing := de.endpointState[directAddr].lastPing == now; gotPing != wantPing {
				t.Errorf("direct endpoint lastPing set = %v, want %v", gotPing, wantPing)
			}
		})
	}
}

func Test_endpoint_updateFromNodeAfterDiscoKeyChange(t *testing.T) {
	relayAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.2:77")}
	relayAddr.vni.Set(1)
	directAddr := epAddr{ap: netip.MustParseAddrPort("192.0.2.1:7")}

	for _, tc := range []struct {
		name       string
		bestAddr   epAddr
		keyChanges bool
	}{
		{
			name:       "relay-bestaddr-key-changed",
			bestAddr:   relayAddr,
			keyChanges: true,
		},
		{
			name:       "direct-bestaddr-key-changed",
			bestAddr:   directAddr,
			keyChanges: true,
		},
		{
			name:       "relay-bestaddr-key-unchanged",
			bestAddr:   relayAddr,
			keyChanges: false,
		},
		{
			name:       "direct-bestaddr-key-unchanged",
			bestAddr:   directAddr,
			keyChanges: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := mono.Now()
			c := &Conn{
				logf: func(msg string, args ...any) {},
			}
			c.discoAtomic.Set(key.NewDisco())
			c.relayManager.hasPeerRelayServers.Store(true)

			oldKey := key.NewDisco().Public()
			de := &endpoint{
				c:                  c,
				publicKey:          key.NewNode().Public(),
				bestAddr:           addrQuality{epAddr: tc.bestAddr},
				trustBestAddrUntil: now.Add(time.Hour),
				sentPing:           make(map[stun.TxID]sentPing),
				endpointState:      make(map[netip.AddrPort]*endpointState),
				debugUpdates:       ringlog.New[EndpointChange](10),
			}
			de.lastUDPRelayPathDiscovery = mono.Now()
			de.disco.Store(&endpointDisco{controlKey: oldKey, controlShort: oldKey.ShortString()})

			incomingKey := oldKey
			if tc.keyChanges {
				incomingKey = key.NewDisco().Public()
			}
			nv := (&tailcfg.Node{
				ID:       1,
				Key:      key.NewNode().Public(),
				DiscoKey: incomingKey,
				HomeDERP: 1,
				Cap:      121, // capVerIsRelayCapable
			}).View()
			de.updateFromNode(nv, false, false)

			de.mu.Lock()
			got := de.wantUDPRelayPathDiscoveryLocked(now)
			de.mu.Unlock()
			if got != tc.keyChanges {
				t.Errorf("wantUDPRelayPathDiscoveryLocked = %v, want %v", got, tc.keyChanges)
			}
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

// TestUpdateFromNodeUsesControlKeyForComparison verifies that updateFromNode
// compares the netmap-provided disco key against the endpoint's control-learned
// key (keyFromControl), not the currently active key (key()).
// Some of this is scaffold for later changes.
func TestUpdateFromNodeUsesControlKeyForComparison(t *testing.T) {
	dk1 := key.NewDisco().Public() // initial control key
	dk2 := key.NewDisco().Public() // TSMP key

	tests := []struct {
		name           string
		netmapDiscoKey key.DiscoPublic
		wantControlKey key.DiscoPublic
		wantActiveKey  key.DiscoPublic
		wantTsmpActive bool
	}{
		{
			name:           "control_catches_up_to_tsmp_key",
			netmapDiscoKey: dk2,
			wantControlKey: dk2,
			wantActiveKey:  dk2,
			wantTsmpActive: false,
		},
		{
			name:           "unchanged_netmap_key_preserves_active",
			netmapDiscoKey: dk1,
			wantControlKey: dk1,
			wantActiveKey:  dk2,
			wantTsmpActive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			de.updateDiscoKey(dk1)
			de.updateTSMPDiscoKey(dk2)

			// Calls updateDiscoKey() internally and sets the endpoint `disco` field.
			de.updateFromNode(
				(&tailcfg.Node{Key: de.publicKey, DiscoKey: tt.netmapDiscoKey}).View(),
				false, false)

			epDisco := de.disco.Load()
			if got := epDisco.keyFromControl(); got != tt.wantControlKey {
				t.Errorf("keyFromControl: got %v, want %v", got, tt.wantControlKey)
			}
			if got := epDisco.tsmpActive; got != tt.wantTsmpActive {
				t.Errorf("tsmpActive: got %t, want %t", got, tt.wantTsmpActive)
			}
			if got := epDisco.key(); got != tt.wantActiveKey {
				t.Errorf("key(): got %v, want %v", got, tt.wantActiveKey)
			}
		})
	}
}

func TestSawDiscoKey(t *testing.T) {
	controlKey := key.NewDisco().Public()
	tsmpKey := key.NewDisco().Public()
	unknownKey := key.NewDisco().Public()
	controlKey2 := key.NewDisco().Public()

	tests := []struct {
		name           string
		initial        *endpointDisco
		seen           key.DiscoPublic
		hook           func(de *endpoint) // injected between Load and CAS; nil = no hook
		wantResult     bool
		wantNil        bool
		wantTsmpActive bool // checked only when initial != nil
		wantCalled     bool // whether changedActiveDisco should be called
	}{
		{
			name:       "nil-disco",
			initial:    nil,
			seen:       controlKey,
			wantResult: false,
			wantNil:    true,
		},
		{
			name:           "active-control-key-seen",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:           controlKey,
			wantResult:     true,
			wantTsmpActive: false,
		},
		{
			name:           "active-tsmp-key-seen",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: true},
			seen:           tsmpKey,
			wantResult:     true,
			wantTsmpActive: true,
		},
		{
			name:           "inactive-tsmp-key-seen-swaps-to-tsmp-active",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:           tsmpKey,
			wantResult:     true,
			wantTsmpActive: true,
			wantCalled:     true,
		},
		{
			name:           "inactive-control-key-seen-swaps-to-control-active",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: true},
			seen:           controlKey,
			wantResult:     true,
			wantTsmpActive: false,
			wantCalled:     true,
		},
		{
			name:           "unknown-key",
			initial:        &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:           unknownKey,
			wantResult:     false,
			wantTsmpActive: false,
		},
		{
			name:           "only-control-key-seen",
			initial:        &endpointDisco{controlKey: controlKey},
			seen:           controlKey,
			wantResult:     true,
			wantTsmpActive: false,
		},
		{
			name:           "only-tsmp-key-seen",
			initial:        &endpointDisco{tsmpKey: tsmpKey, tsmpActive: true},
			seen:           tsmpKey,
			wantResult:     true,
			wantTsmpActive: true,
		},
		{
			// Hook fires once and replaces the struct (same tsmpKey, different controlKey),
			// forcing the first CAS to fail. The retry should still find tsmpKey as the
			// inactive key and succeed.
			name:    "CAS-retry-on-concurrent-update",
			initial: &endpointDisco{controlKey: controlKey, tsmpKey: tsmpKey, tsmpActive: false},
			seen:    tsmpKey,
			hook: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: controlKey2,
					tsmpKey:    tsmpKey,
					tsmpActive: false,
				})
			},
			wantResult:     true,
			wantTsmpActive: true,
			wantCalled:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			if tt.initial != nil {
				de.disco.Store(tt.initial)
			}

			if tt.wantCalled {
				de.trustBestAddrUntil = mono.Now().Add(time.Hour)
			}

			hookFired := false
			if tt.hook != nil {
				sawDiscoKeyTestHook = func() {
					if !hookFired {
						hookFired = true
						tt.hook(de)
					}
				}
				t.Cleanup(func() { sawDiscoKeyTestHook = nil })
			}

			epDisco, got := de.checkAndUpdateDiscoKey(tt.seen)

			if got != tt.wantResult {
				t.Errorf("sawDiscoKey().seen = %v, want %v", got, tt.wantResult)
			}
			if tt.wantNil && epDisco != nil {
				t.Errorf("sawDiscoKey().epDisco = %v, want %v", epDisco, nil)
			}
			if tt.hook != nil && !hookFired {
				t.Error("test hook was never called; CAS retry path not exercised")
			}
			if tt.initial != nil {
				if active := de.disco.Load(); active.tsmpActive != tt.wantTsmpActive {
					t.Errorf("after call: tsmpActive = %v, want %v", active.tsmpActive, tt.wantTsmpActive)
				}
			}
			if tt.wantCalled && de.trustBestAddrUntil != 0 {
				t.Errorf("de.trustBedstAddrUntil expected to be 0, got %d", de.trustBestAddrUntil)
			}
		})
	}
}

func TestUpdateDiscoKey(t *testing.T) {
	dk1 := key.NewDisco().Public()
	dk2 := key.NewDisco().Public()
	dk3 := key.NewDisco().Public()
	zero := key.DiscoPublic{}

	tests := []struct {
		name          string
		setup         func(de *endpoint)
		newKey        key.DiscoPublic
		wantChanged   bool
		wantActiveKey key.DiscoPublic
	}{
		{
			name:          "first-key-set",
			newKey:        dk1,
			wantChanged:   true,
			wantActiveKey: dk1,
		},
		{
			name: "same-control-key-no-change",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{controlKey: dk1, controlShort: dk1.ShortString()})
			},
			newKey:        dk1,
			wantChanged:   false,
			wantActiveKey: dk1,
		},
		{
			name: "control-key-rotates-while-control-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{controlKey: dk1, controlShort: dk1.ShortString()})
			},
			newKey:        dk2,
			wantChanged:   true,
			wantActiveKey: dk2,
		},
		{
			name: "control-key-rotates-while-tsmp-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(),
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
					tsmpActive: true,
				})
			},
			newKey:        dk3,
			wantChanged:   true,
			wantActiveKey: dk3,
		},
		{
			name: "control-key-cleared-tsmp-present",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(),
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
					tsmpActive: false,
				})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: dk2,
		},
		{
			name: "control-key-cleared-no-tsmp",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{controlKey: dk1, controlShort: dk1.ShortString()})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: zero,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			if tt.setup != nil {
				tt.setup(de)
			}

			if got := de.updateDiscoKey(tt.newKey); got != tt.wantChanged {
				t.Errorf("expected de.updateDiscoKey()=%t, got %t", tt.wantChanged, got)
			}
			if got := de.disco.Load().key(); got != tt.wantActiveKey {
				t.Errorf("active key: got %v, want %v", got, tt.wantActiveKey)
			}
		})
	}
}

func TestUpdateTSMPDiscoKey(t *testing.T) {
	dk1 := key.NewDisco().Public()
	dk2 := key.NewDisco().Public()
	dk3 := key.NewDisco().Public()
	zero := key.DiscoPublic{}

	tests := []struct {
		name          string
		setup         func(de *endpoint)
		newKey        key.DiscoPublic
		wantChanged   bool
		wantActiveKey key.DiscoPublic
	}{
		{
			name:          "first-tsmp-key-set",
			newKey:        dk1,
			wantChanged:   true,
			wantActiveKey: dk1,
		},
		{
			name: "same-tsmp-key-no-change",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{tsmpKey: dk1, tsmpShort: dk1.ShortString(), tsmpActive: true})
			},
			newKey:        dk1,
			wantChanged:   false,
			wantActiveKey: dk1,
		},
		{
			name: "tsmp-key-rotates-while-tsmp-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{tsmpKey: dk1, tsmpShort: dk1.ShortString(), tsmpActive: true})
			},
			newKey:        dk2,
			wantChanged:   true,
			wantActiveKey: dk2,
		},
		{
			name: "tsmp-key-set-while-tsmp-active",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(), tsmpActive: true,
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
				})
			},
			newKey:        dk3,
			wantChanged:   true,
			wantActiveKey: dk3,
		},
		{
			name: "tsmp-key-cleared-control-present",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{
					controlKey: dk1, controlShort: dk1.ShortString(),
					tsmpKey: dk2, tsmpShort: dk2.ShortString(),
					tsmpActive: true,
				})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: dk1,
		},
		{
			name: "tsmp-key-cleared-no-control",
			setup: func(de *endpoint) {
				de.disco.Store(&endpointDisco{tsmpKey: dk2, tsmpShort: dk2.ShortString(), tsmpActive: true})
			},
			newKey:        zero,
			wantChanged:   true,
			wantActiveKey: zero,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(msg string, args ...any) {}}}
			if tt.setup != nil {
				tt.setup(de)
			}

			if got := de.updateTSMPDiscoKey(tt.newKey); got != tt.wantChanged {
				t.Errorf("expected de.updateDiscoKey()=%t, got %t", tt.wantChanged, got)
			}
			if got := de.disco.Load().key(); got != tt.wantActiveKey {
				t.Errorf("active key: got %v, want %v", got, tt.wantActiveKey)
			}
		})
	}
}

// TestUpdateFromNodeChangedActiveDisco verifies that updateFromNode resets
// trustBestAddrUntil (via changedActiveDisco) when the control disco key
// changes, and leaves it untouched when the key is unchanged.
func TestUpdateFromNodeChangedActiveDisco(t *testing.T) {
	dk1 := key.NewDisco().Public()
	dk2 := key.NewDisco().Public()

	tests := []struct {
		name           string
		initialControl key.DiscoPublic
		netmapKey      key.DiscoPublic
		wantCalled     bool
	}{
		{
			name:           "control-key-changes-fires",
			initialControl: dk1,
			netmapKey:      dk2,
			wantCalled:     true,
		},
		{
			name:           "control-key-unchanged-no-fire",
			initialControl: dk1,
			netmapKey:      dk1,
			wantCalled:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			de := &endpoint{c: &Conn{logf: func(string, ...any) {}}}
			de.disco.Store(&endpointDisco{controlKey: tt.initialControl, controlShort: tt.initialControl.ShortString()})

			// Set a future trustBestAddrUntil so we can detect if it was zeroed.
			de.trustBestAddrUntil = mono.Now().Add(time.Hour)
			before := de.trustBestAddrUntil

			de.updateFromNode(
				(&tailcfg.Node{Key: de.publicKey, DiscoKey: tt.netmapKey}).View(),
				false, false)

			addrUntil := de.trustBestAddrUntil
			if tt.wantCalled && addrUntil != 0 {
				t.Errorf("trustBestAddrUntil not reset: got %v, want 0", addrUntil)
			}
			if !tt.wantCalled && addrUntil != before {
				t.Errorf("trustBestAddrUntil unexpectedly changed from %v to %v", before, addrUntil)
			}
		})
	}
}

func TestChangedActiveDiscoLocked(t *testing.T) {
	t.Run("resets-trustBestAddrUntil", func(t *testing.T) {
		de := &endpoint{}
		de.trustBestAddrUntil = mono.Now().Add(time.Hour)
		de.mu.Lock()
		de.changedActiveDiscoLocked()
		de.mu.Unlock()
		if de.trustBestAddrUntil != 0 {
			t.Errorf("trustBestAddrUntil not reset to zero, got %v", de.trustBestAddrUntil)
		}
	})

	t.Run("invalidates-disco-path-fields", func(t *testing.T) {
		de := &endpoint{}
		de.lastSendExt = mono.Now()
		de.lastFullPing = mono.Now()
		de.lastUDPRelayPathDiscovery = mono.Now()
		de.isWireguardOnly = true // avoid sentPing iteration, which requires de.c
		de.mu.Lock()
		de.changedActiveDiscoLocked()
		de.mu.Unlock()
		if de.lastSendExt != 0 {
			t.Error("lastSendExt not reset to zero")
		}
		if de.lastFullPing != 0 {
			t.Error("lastFullPing not reset to zero")
		}
		if de.lastUDPRelayPathDiscovery != 0 {
			t.Error("lastUDPRelayPathDiscovery not reset to zero")
		}
	})
}
