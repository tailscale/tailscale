// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime/mono"
	"tailscale.com/types/key"
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
	var lower, higher key.DiscoPublic
	a := key.NewDisco().Public()
	b := key.NewDisco().Public()
	if a.String() < b.String() {
		lower = a
		higher = b
	} else {
		lower = b
		higher = a
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
			name:        "nil probeUDPLifetime",
			localDisco:  higher,
			remoteDisco: &lower,
			probeUDPLifetimeFn: func() *probeUDPLifetime {
				return nil
			},
			bestAddr: addr,
		},
		{
			name:               "local higher disco key",
			localDisco:         higher,
			remoteDisco:        &lower,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addr,
		},
		{
			name:               "remote no disco key",
			localDisco:         higher,
			remoteDisco:        nil,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addr,
		},
		{
			name:               "invalid bestAddr",
			localDisco:         lower,
			remoteDisco:        &higher,
			probeUDPLifetimeFn: newProbeUDPLifetime,
			bestAddr:           addrQuality{},
		},
		{
			name:        "cycle started too recently",
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
			name:        "maybe cliff 0 cycle not active",
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
			name:        "maybe cliff 0",
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
			name:        "maybe cliff 1",
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
			name:        "maybe cliff 2",
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
			de := &endpoint{
				c: &Conn{
					discoPublic: tt.localDisco,
				},
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
			name: "false derp magic addr",
			ap:   netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 0),
			vni:  packet.VirtualNetworkID{},
			want: false,
		},
		{
			name: "false vni set",
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
			name:               "bestAddr trusted direct",
			curBestAddr:        directAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQuality,
			wantBestAddr:       directAddrQuality,
		},
		{
			name:               "bestAddr untrusted direct",
			curBestAddr:        directAddrQuality,
			trustBestAddrUntil: mono.Now().Add(-1 * time.Hour),
			maybeBest:          peerRelayAddrQuality,
			wantBestAddr:       peerRelayAddrQuality,
		},
		{
			name:               "maybeBest same relay server higher latency bestAddr trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityHigherLatencySameServer,
			wantBestAddr:       peerRelayAddrQualityHigherLatencySameServer,
		},
		{
			name:               "maybeBest diff relay server higher latency bestAddr trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityHigherLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQuality,
		},
		{
			name:               "maybeBest diff relay server lower latency bestAddr trusted",
			curBestAddr:        peerRelayAddrQuality,
			trustBestAddrUntil: mono.Now().Add(1 * time.Hour),
			maybeBest:          peerRelayAddrQualityLowerLatencyDiffServer,
			wantBestAddr:       peerRelayAddrQualityLowerLatencyDiffServer,
		},
		{
			name:               "maybeBest diff relay server equal latency bestAddr trusted",
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
