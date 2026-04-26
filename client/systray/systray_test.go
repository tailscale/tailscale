// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

package systray

import (
	"slices"
	"testing"

	"fyne.io/systray"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// mkExitPeer creates a Mullvad-shaped exit-node peer at the given location.
func mkExitPeer(id, country, countryCode, city, cityCode string, priority int) *ipnstate.PeerStatus {
	return &ipnstate.PeerStatus{
		ID:             tailcfg.StableNodeID(id),
		ExitNodeOption: true,
		Location: &tailcfg.Location{
			Country:     country,
			CountryCode: countryCode,
			City:        city,
			CityCode:    cityCode,
			Priority:    priority,
		},
	}
}

// statusWith returns a Status whose Peer map contains the given peers, each
// keyed by a freshly generated NodePublic so the map can hold them all.
func statusWith(peers ...*ipnstate.PeerStatus) *ipnstate.Status {
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{}}
	for _, p := range peers {
		st.Peer[key.NewNode().Public()] = p
	}
	return st
}

func TestNewMullvadPeers(t *testing.T) {
	st := statusWith(
		mkExitPeer("us-nyc-1", "United States", "US", "New York", "NYC", 50),
		mkExitPeer("us-la-1", "United States", "US", "Los Angeles", "LAX", 40),
		mkExitPeer("us-la-2", "United States", "US", "Los Angeles", "LAX", 90),
		mkExitPeer("jp-tyo-1", "Japan", "JP", "Tokyo", "TYO", 60),
		// A non-Mullvad exit-node-eligible peer (Location nil) — must be
		// excluded from mullvad grouping.
		&ipnstate.PeerStatus{ID: "tailnet-exit", ExitNodeOption: true},
		// A regular non-exit peer — also excluded.
		&ipnstate.PeerStatus{ID: "regular"},
	)

	got := newMullvadPeers(st)

	if len(got.countries) != 2 {
		t.Fatalf("got %d countries, want 2 (US, JP)", len(got.countries))
	}

	us, ok := got.countries["US"]
	if !ok {
		t.Fatal("missing US country")
	}
	if us.best == nil || us.best.ID != "us-la-2" {
		t.Errorf("US best = %v, want us-la-2 (highest priority)", us.best)
	}
	if la := us.cities["LAX"]; la == nil || la.best.ID != "us-la-2" || len(la.peers) != 2 {
		t.Errorf("LAX = %v, want best=us-la-2 with 2 peers", la)
	}
	if jp := got.countries["JP"]; jp == nil || jp.best.ID != "jp-tyo-1" {
		t.Errorf("JP best = %v, want jp-tyo-1", jp)
	}
}

func TestSortedCountriesAndCities(t *testing.T) {
	st := statusWith(
		mkExitPeer("uk", "United Kingdom", "GB", "London", "LON", 1),
		mkExitPeer("us-1", "United States", "US", "Boston", "BOS", 1),
		mkExitPeer("us-2", "United States", "US", "Atlanta", "ATL", 1),
		mkExitPeer("at", "Austria", "AT", "Vienna", "VIE", 1),
	)
	mp := newMullvadPeers(st)

	gotCountries := []string{}
	for _, c := range mp.sortedCountries() {
		gotCountries = append(gotCountries, c.name)
	}
	wantCountries := []string{"Austria", "United Kingdom", "United States"}
	if !slices.Equal(gotCountries, wantCountries) {
		t.Errorf("sortedCountries = %v, want %v", gotCountries, wantCountries)
	}

	gotCities := []string{}
	for _, c := range mp.countries["US"].sortedCities() {
		gotCities = append(gotCities, c.name)
	}
	wantCities := []string{"Atlanta", "Boston"}
	if !slices.Equal(gotCities, wantCities) {
		t.Errorf("US sortedCities = %v, want %v", gotCities, wantCities)
	}
}

func TestActiveExitNodeID(t *testing.T) {
	const id tailcfg.StableNodeID = "exit-node-1"

	tests := []struct {
		name   string
		prefs  *ipn.Prefs
		status *ipnstate.Status
		want   tailcfg.StableNodeID
	}{
		{
			name: "neither set",
			want: "",
		},
		{
			name:  "prefs set, peer in netmap",
			prefs: &ipn.Prefs{ExitNodeID: id},
			status: &ipnstate.Status{
				ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: id, Online: true},
			},
			want: id,
		},
		{
			name:   "prefs set, peer missing from netmap",
			prefs:  &ipn.Prefs{ExitNodeID: id},
			status: &ipnstate.Status{},
			want:   id,
		},
		{
			name:   "prefs nil, status fallback",
			status: &ipnstate.Status{ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: id}},
			want:   id,
		},
		{
			name:   "prefs zero, status fallback",
			prefs:  &ipn.Prefs{},
			status: &ipnstate.Status{ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: id}},
			want:   id,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := activeExitNodeID(tt.prefs, tt.status); got != tt.want {
				t.Errorf("activeExitNodeID = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppearance(t *testing.T) {
	const id tailcfg.StableNodeID = "exit-node-1"
	tailnet := &ipnstate.TailnetStatus{Name: "tailnet"}

	tests := []struct {
		name        string
		prefs       *ipn.Prefs
		status      *ipnstate.Status
		wantIcon    *tsLogo
		wantTooltip string
	}{
		{
			name:        "nil status",
			wantIcon:    &disconnected,
			wantTooltip: "Disconnected",
		},
		{
			name:        "starting",
			status:      &ipnstate.Status{BackendState: ipn.Starting.String()},
			wantIcon:    &loading,
			wantTooltip: "Connecting",
		},
		{
			name: "running, no exit node",
			status: &ipnstate.Status{
				BackendState:   ipn.Running.String(),
				CurrentTailnet: tailnet,
			},
			wantIcon:    &connected,
			wantTooltip: "Connected to tailnet",
		},
		{
			name:  "running, exit node online",
			prefs: &ipn.Prefs{ExitNodeID: id},
			status: &ipnstate.Status{
				BackendState:   ipn.Running.String(),
				CurrentTailnet: tailnet,
				ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: id, Online: true},
			},
			wantIcon:    &exitNodeOnline,
			wantTooltip: "Using exit node",
		},
		{
			name:  "running, exit node in netmap but offline",
			prefs: &ipn.Prefs{ExitNodeID: id},
			status: &ipnstate.Status{
				BackendState:   ipn.Running.String(),
				CurrentTailnet: tailnet,
				ExitNodeStatus: &ipnstate.ExitNodeStatus{ID: id, Online: false},
			},
			wantIcon:    &exitNodeOffline,
			wantTooltip: "Exit node offline",
		},
		{
			name:  "running, exit node configured but missing from netmap",
			prefs: &ipn.Prefs{ExitNodeID: id},
			status: &ipnstate.Status{
				BackendState:   ipn.Running.String(),
				CurrentTailnet: tailnet,
			},
			wantIcon:    &exitNodeOffline,
			wantTooltip: "Exit node offline",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIcon, gotTooltip := appearance(tt.status, tt.prefs)
			if gotIcon != tt.wantIcon {
				t.Errorf("icon = %p, want %p", gotIcon, tt.wantIcon)
			}
			if gotTooltip != tt.wantTooltip {
				t.Errorf("tooltip = %q, want %q", gotTooltip, tt.wantTooltip)
			}
		})
	}
}

// TestShortCircuitCaches verifies the cache field is the only signal of
// whether the underlying fyne mutator runs: fyne exposes no title getter
// and refresh() is a no-op without a dbus connection, so the cache value
// is the only externally observable contract.
func TestShortCircuitCaches(t *testing.T) {
	item := systray.AddMenuItem("probe", "")

	t.Run("setTitleIfChanged", func(t *testing.T) {
		var cache string
		setTitleIfChanged(&cache, item, "alpha")
		if cache != "alpha" {
			t.Fatalf("after first set, cache = %q, want alpha", cache)
		}

		setTitleIfChanged(&cache, item, "alpha")
		if cache != "alpha" {
			t.Fatalf("no-op mutated cache: %q", cache)
		}

		setTitleIfChanged(&cache, item, "beta")
		if cache != "beta" {
			t.Fatalf("transition cache = %q, want beta", cache)
		}

		setTitleIfChanged(&cache, nil, "gamma")
		if cache != "beta" {
			t.Fatalf("nil item mutated cache: %q", cache)
		}
	})

	t.Run("setVisibleIfChanged", func(t *testing.T) {
		var cache bool
		setVisibleIfChanged(&cache, item, true)
		if !cache {
			t.Fatal("after Show, cache should be true")
		}

		setVisibleIfChanged(&cache, item, true)
		if !cache {
			t.Fatal("no-op flipped cache")
		}

		setVisibleIfChanged(&cache, item, false)
		if cache {
			t.Fatal("after Hide, cache should be false")
		}

		setVisibleIfChanged(&cache, nil, true)
		if cache {
			t.Fatal("nil item mutated cache")
		}
	})

	t.Run("Menu.setTooltipIfChanged", func(t *testing.T) {
		m := &Menu{}
		m.setTooltipIfChanged("hello")
		if m.lastTooltip != "hello" {
			t.Fatalf("lastTooltip = %q, want hello", m.lastTooltip)
		}

		m.setTooltipIfChanged("hello")
		if m.lastTooltip != "hello" {
			t.Fatalf("no-op mutated lastTooltip: %q", m.lastTooltip)
		}

		m.setTooltipIfChanged("world")
		if m.lastTooltip != "world" {
			t.Fatalf("lastTooltip = %q, want world", m.lastTooltip)
		}
	})

	t.Run("Menu.setAppIconIfChanged", func(t *testing.T) {
		m := &Menu{}
		m.setAppIconIfChanged(&disconnected)
		if m.lastIcon != &disconnected {
			t.Fatal("lastIcon should be &disconnected")
		}

		m.setAppIconIfChanged(&disconnected)
		if m.lastIcon != &disconnected {
			t.Fatal("no-op mutated lastIcon")
		}

		m.setAppIconIfChanged(&connected)
		if m.lastIcon != &connected {
			t.Fatal("lastIcon should be &connected after transition")
		}
	})
}

// statusWithSelf returns a Status whose Self is non-nil, with the mullvad
// capability either set or unset.
func statusWithSelf(mullvad bool) *ipnstate.Status {
	st := &ipnstate.Status{
		Peer: map[key.NodePublic]*ipnstate.PeerStatus{},
		Self: &ipnstate.PeerStatus{},
	}
	if mullvad {
		st.Self.CapMap = tailcfg.NodeCapMap{"mullvad": nil}
	}
	return st
}

func TestComputeShape(t *testing.T) {
	pa := ipn.LoginProfile{ID: "A"}
	pb := ipn.LoginProfile{ID: "B"}
	pc := ipn.LoginProfile{ID: "C"}

	t.Run("readonly differs", func(t *testing.T) {
		s1 := computeShape(nil, ipn.LoginProfile{}, nil, false)
		s2 := computeShape(nil, ipn.LoginProfile{}, nil, true)

		if s1 == s2 {
			t.Error("readonly change did not produce different shape")
		}
	})

	t.Run("profile add changes shape", func(t *testing.T) {
		s1 := computeShape(nil, pa, []ipn.LoginProfile{pa, pb}, false)
		s2 := computeShape(nil, pa, []ipn.LoginProfile{pa, pb, pc}, false)

		if s1 == s2 {
			t.Error("profile add did not change shape")
		}
	})

	t.Run("profile order does not change shape", func(t *testing.T) {
		s1 := computeShape(nil, pa, []ipn.LoginProfile{pa, pb, pc}, false)
		s2 := computeShape(nil, pa, []ipn.LoginProfile{pc, pa, pb}, false)

		if s1 != s2 {
			t.Errorf("profile reordering changed shape: %+v vs %+v", s1, s2)
		}
	})

	t.Run("current profile change moves shape", func(t *testing.T) {
		s1 := computeShape(nil, pa, []ipn.LoginProfile{pa, pb}, false)
		s2 := computeShape(nil, pb, []ipn.LoginProfile{pa, pb}, false)

		if s1 == s2 {
			t.Error("current profile change did not move shape")
		}
	})

	t.Run("tailnet exit node add changes shape", func(t *testing.T) {
		st1 := statusWith(&ipnstate.PeerStatus{ID: "p1", ExitNodeOption: true})
		st2 := statusWith(
			&ipnstate.PeerStatus{ID: "p1", ExitNodeOption: true},
			&ipnstate.PeerStatus{ID: "p2", ExitNodeOption: true},
		)
		s1 := computeShape(st1, ipn.LoginProfile{}, nil, false)
		s2 := computeShape(st2, ipn.LoginProfile{}, nil, false)

		if s1 == s2 {
			t.Error("tailnet exit node add did not change shape")
		}
	})

	t.Run("non-exit peer does not change shape", func(t *testing.T) {
		st1 := statusWithSelf(false)
		st2 := statusWithSelf(false)
		st2.Peer[key.NewNode().Public()] = &ipnstate.PeerStatus{ID: "p1"}
		s1 := computeShape(st1, ipn.LoginProfile{}, nil, false)
		s2 := computeShape(st2, ipn.LoginProfile{}, nil, false)

		if s1 != s2 {
			t.Errorf("non-exit peer changed shape: %+v vs %+v", s1, s2)
		}
	})

	t.Run("mullvad gated by capability", func(t *testing.T) {
		mvPeer := mkExitPeer("mv-1", "United States", "US", "New York", "NYC", 1)
		without := statusWithSelf(false)
		without.Peer[key.NewNode().Public()] = mvPeer

		if s := computeShape(without, ipn.LoginProfile{}, nil, false); s.mullvadEnabled {
			t.Error("mullvad enabled without capability")
		}

		with := statusWithSelf(true)
		with.Peer[key.NewNode().Public()] = mvPeer
		s := computeShape(with, ipn.LoginProfile{}, nil, false)

		if !s.mullvadEnabled || s.mullvadKey == "" {
			t.Errorf("mullvad not enabled with capability: %+v", s)
		}
	})
}
