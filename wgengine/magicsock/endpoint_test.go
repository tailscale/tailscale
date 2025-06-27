// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"
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
			"nil probeUDPLifetime",
			higher,
			&lower,
			func() *probeUDPLifetime {
				return nil
			},
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return 0
			},
			false,
		},
		{
			"local higher disco key",
			higher,
			&lower,
			newProbeUDPLifetime,
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return 0
			},
			false,
		},
		{
			"remote no disco key",
			higher,
			nil,
			newProbeUDPLifetime,
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return 0
			},
			false,
		},
		{
			"invalid bestAddr",
			lower,
			&higher,
			newProbeUDPLifetime,
			addrQuality{},
			func(lifetime *probeUDPLifetime) time.Duration {
				return 0
			},
			false,
		},
		{
			"cycle started too recently",
			lower,
			&higher,
			func() *probeUDPLifetime {
				l := newProbeUDPLifetime()
				l.cycleActive = false
				l.cycleStartedAt = time.Now()
				return l
			},
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return 0
			},
			false,
		},
		{
			"maybe cliff 0 cycle not active",
			lower,
			&higher,
			func() *probeUDPLifetime {
				l := newProbeUDPLifetime()
				l.cycleActive = false
				l.cycleStartedAt = time.Now().Add(-l.config.CycleCanStartEvery).Add(-time.Second)
				return l
			},
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[0] - udpLifetimeProbeCliffSlack
			},
			true,
		},
		{
			"maybe cliff 0",
			lower,
			&higher,
			func() *probeUDPLifetime {
				l := newProbeUDPLifetime()
				l.cycleActive = true
				l.currentCliff = 0
				return l
			},
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[0] - udpLifetimeProbeCliffSlack
			},
			true,
		},
		{
			"maybe cliff 1",
			lower,
			&higher,
			func() *probeUDPLifetime {
				l := newProbeUDPLifetime()
				l.cycleActive = true
				l.currentCliff = 1
				return l
			},
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[1] - udpLifetimeProbeCliffSlack
			},
			true,
		},
		{
			"maybe cliff 2",
			lower,
			&higher,
			func() *probeUDPLifetime {
				l := newProbeUDPLifetime()
				l.cycleActive = true
				l.currentCliff = 2
				return l
			},
			addr,
			func(lifetime *probeUDPLifetime) time.Duration {
				return lifetime.config.Cliffs[2] - udpLifetimeProbeCliffSlack
			},
			true,
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
			wantAfterInactivityFor := tt.wantAfterInactivityForFn(p)
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
	vni := virtualNetworkID{}
	vni.set(7)
	tests := []struct {
		name string
		ap   netip.AddrPort
		vni  virtualNetworkID
		want bool
	}{
		{
			name: "true",
			ap:   netip.MustParseAddrPort("192.0.2.1:7"),
			vni:  virtualNetworkID{},
			want: true,
		},
		{
			name: "false derp magic addr",
			ap:   netip.AddrPortFrom(tailcfg.DerpMagicIPAddr, 0),
			vni:  virtualNetworkID{},
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
