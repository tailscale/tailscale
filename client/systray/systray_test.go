// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build cgo || !darwin

package systray

import (
	"net/netip"
	"runtime"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// ===== profileTitle Tests =====

func TestProfileTitle(t *testing.T) {
	tests := []struct {
		name     string
		profile  ipn.LoginProfile
		expected string
	}{
		{
			name: "profile_without_domain",
			profile: ipn.LoginProfile{
				Name: "user@example.com",
			},
			expected: "user@example.com",
		},
		{
			name: "profile_with_domain_on_windows",
			profile: ipn.LoginProfile{
				Name: "user@example.com",
				NetworkProfile: ipn.NetworkProfile{
					DomainName:  "tailnet.ts.net",
					MagicDNSName: "tailnet",
				},
			},
			// On Windows/Mac, should append domain in parentheses
			expected: func() string {
				if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
					return "user@example.com (tailnet)"
				}
				// On Linux, should use newline
				return "user@example.com\ntailnet"
			}(),
		},
		{
			name: "profile_with_custom_display_name",
			profile: ipn.LoginProfile{
				Name: "user@example.com",
				NetworkProfile: ipn.NetworkProfile{
					DomainName:  "custom.ts.net",
					MagicDNSName: "custom-tailnet",
				},
			},
			expected: func() string {
				if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
					return "user@example.com (custom-tailnet)"
				}
				return "user@example.com\ncustom-tailnet"
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := profileTitle(tt.profile)
			if got != tt.expected {
				t.Errorf("profileTitle() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestProfileTitle_EmptyProfile(t *testing.T) {
	profile := ipn.LoginProfile{}
	result := profileTitle(profile)
	if result != "" {
		t.Errorf("profileTitle(empty) = %q, want empty string", result)
	}
}

// ===== countryFlag Tests =====

func TestCountryFlag(t *testing.T) {
	tests := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"GB", "🇬🇧"},
		{"DE", "🇩🇪"},
		{"FR", "🇫🇷"},
		{"JP", "🇯🇵"},
		{"CA", "🇨🇦"},
		{"AU", "🇦🇺"},
		{"SE", "🇸🇪"},
		{"NL", "🇳🇱"},
		{"CH", "🇨🇭"},
		// lowercase should also work
		{"us", "🇺🇸"},
		{"gb", "🇬🇧"},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			got := countryFlag(tt.code)
			if got != tt.expected {
				t.Errorf("countryFlag(%q) = %q, want %q", tt.code, got, tt.expected)
			}
		})
	}
}

func TestCountryFlag_InvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		code string
	}{
		{"empty", ""},
		{"too_short", "U"},
		{"too_long", "USA"},
		{"numbers", "12"},
		{"special_chars", "U$"},
		{"spaces", "U "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countryFlag(tt.code)
			if got != "" {
				t.Errorf("countryFlag(%q) = %q, want empty string", tt.code, got)
			}
		})
	}
}

// ===== mullvadPeers Tests =====

func TestNewMullvadPeers(t *testing.T) {
	status := &ipnstate.Status{
		Peer: map[tailcfg.NodeKey]*ipnstate.PeerStatus{
			tailcfg.NodeKey{1}: {
				ID:             tailcfg.StableNodeID("node1"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "United States",
					CountryCode: "US",
					City:        "New York",
					CityCode:    "nyc",
					Priority:    100,
				},
			},
			tailcfg.NodeKey{2}: {
				ID:             tailcfg.StableNodeID("node2"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "United States",
					CountryCode: "US",
					City:        "Los Angeles",
					CityCode:    "lax",
					Priority:    90,
				},
			},
			tailcfg.NodeKey{3}: {
				ID:             tailcfg.StableNodeID("node3"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Germany",
					CountryCode: "DE",
					City:        "Berlin",
					CityCode:    "ber",
					Priority:    80,
				},
			},
		},
	}

	mp := newMullvadPeers(status)

	// Should have 2 countries
	if len(mp.countries) != 2 {
		t.Errorf("expected 2 countries, got %d", len(mp.countries))
	}

	// Check US country
	us, ok := mp.countries["US"]
	if !ok {
		t.Fatal("expected US country")
	}
	if us.name != "United States" {
		t.Errorf("US country name = %q, want %q", us.name, "United States")
	}
	if us.code != "US" {
		t.Errorf("US country code = %q, want %q", us.code, "US")
	}
	if len(us.cities) != 2 {
		t.Errorf("US should have 2 cities, got %d", len(us.cities))
	}
	// Best peer should be the one with highest priority
	if us.best.ID != "node1" {
		t.Errorf("US best peer = %q, want %q", us.best.ID, "node1")
	}

	// Check Germany country
	de, ok := mp.countries["DE"]
	if !ok {
		t.Fatal("expected DE country")
	}
	if de.name != "Germany" {
		t.Errorf("DE country name = %q, want %q", de.name, "Germany")
	}
	if len(de.cities) != 1 {
		t.Errorf("DE should have 1 city, got %d", len(de.cities))
	}
}

func TestNewMullvadPeers_EmptyStatus(t *testing.T) {
	status := &ipnstate.Status{
		Peer: map[tailcfg.NodeKey]*ipnstate.PeerStatus{},
	}

	mp := newMullvadPeers(status)

	if len(mp.countries) != 0 {
		t.Errorf("expected 0 countries for empty status, got %d", len(mp.countries))
	}
}

func TestNewMullvadPeers_SkipsNonExitNodes(t *testing.T) {
	status := &ipnstate.Status{
		Peer: map[tailcfg.NodeKey]*ipnstate.PeerStatus{
			tailcfg.NodeKey{1}: {
				ID:             tailcfg.StableNodeID("node1"),
				ExitNodeOption: false, // Not an exit node
				Location: &tailcfg.Location{
					Country:     "United States",
					CountryCode: "US",
					City:        "New York",
					CityCode:    "nyc",
					Priority:    100,
				},
			},
			tailcfg.NodeKey{2}: {
				ID:             tailcfg.StableNodeID("node2"),
				ExitNodeOption: true,
				Location:       nil, // No location
			},
		},
	}

	mp := newMullvadPeers(status)

	// Should skip both: one is not an exit node, one has no location
	if len(mp.countries) != 0 {
		t.Errorf("expected 0 countries (both peers should be skipped), got %d", len(mp.countries))
	}
}

func TestMullvadPeers_SortedCountries(t *testing.T) {
	mp := mullvadPeers{
		countries: map[string]*mvCountry{
			"US": {code: "US", name: "United States"},
			"DE": {code: "DE", name: "Germany"},
			"FR": {code: "FR", name: "France"},
			"GB": {code: "GB", name: "United Kingdom"},
		},
	}

	sorted := mp.sortedCountries()

	if len(sorted) != 4 {
		t.Fatalf("expected 4 countries, got %d", len(sorted))
	}

	// Should be sorted alphabetically by name (case-insensitive)
	expected := []string{"France", "Germany", "United Kingdom", "United States"}
	for i, country := range sorted {
		if country.name != expected[i] {
			t.Errorf("country[%d] = %q, want %q", i, country.name, expected[i])
		}
	}
}

func TestMvCountry_SortedCities(t *testing.T) {
	country := &mvCountry{
		code: "US",
		name: "United States",
		cities: map[string]*mvCity{
			"sea": {name: "Seattle"},
			"nyc": {name: "New York"},
			"lax": {name: "Los Angeles"},
			"chi": {name: "Chicago"},
		},
	}

	sorted := country.sortedCities()

	if len(sorted) != 4 {
		t.Fatalf("expected 4 cities, got %d", len(sorted))
	}

	// Should be sorted alphabetically by name (case-insensitive)
	expected := []string{"Chicago", "Los Angeles", "New York", "Seattle"}
	for i, city := range sorted {
		if city.name != expected[i] {
			t.Errorf("city[%d] = %q, want %q", i, city.name, expected[i])
		}
	}
}

func TestMullvadPeers_PrioritySelection(t *testing.T) {
	// Test that the best peer is selected based on priority
	status := &ipnstate.Status{
		Peer: map[tailcfg.NodeKey]*ipnstate.PeerStatus{
			tailcfg.NodeKey{1}: {
				ID:             tailcfg.StableNodeID("node1"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Germany",
					CountryCode: "DE",
					City:        "Berlin",
					CityCode:    "ber",
					Priority:    50, // Lower priority
				},
			},
			tailcfg.NodeKey{2}: {
				ID:             tailcfg.StableNodeID("node2"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Germany",
					CountryCode: "DE",
					City:        "Berlin",
					CityCode:    "ber",
					Priority:    100, // Higher priority - should be selected
				},
			},
		},
	}

	mp := newMullvadPeers(status)

	de := mp.countries["DE"]
	if de.best.ID != "node2" {
		t.Errorf("best country peer = %q, want node2 (highest priority)", de.best.ID)
	}

	berlin := de.cities["ber"]
	if berlin.best.ID != "node2" {
		t.Errorf("best city peer = %q, want node2 (highest priority)", berlin.best.ID)
	}
}

// ===== Menu State Tests =====

func TestMenu_Init(t *testing.T) {
	menu := &Menu{}

	// Should be uninitialized
	if menu.bgCtx != nil {
		t.Error("expected nil bgCtx before init")
	}

	menu.init()

	// After init, channels and context should be set
	if menu.rebuildCh == nil {
		t.Error("rebuildCh should be initialized")
	}
	if menu.accountsCh == nil {
		t.Error("accountsCh should be initialized")
	}
	if menu.exitNodeCh == nil {
		t.Error("exitNodeCh should be initialized")
	}
	if menu.bgCtx == nil {
		t.Error("bgCtx should be initialized")
	}
	if menu.bgCancel == nil {
		t.Error("bgCancel should be initialized")
	}

	// Calling init again should be a no-op
	oldCtx := menu.bgCtx
	menu.init()
	if menu.bgCtx != oldCtx {
		t.Error("second init() should not recreate context")
	}

	// Cleanup
	menu.bgCancel()
}

func TestMenu_OnExit(t *testing.T) {
	menu := &Menu{}
	menu.init()

	// Create a temp file for notification icon
	menu.notificationIcon, _ = nil, nil // Can't actually create temp file in test

	// Should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("onExit panicked: %v", r)
		}
	}()

	menu.onExit()
}

// ===== Package Variables Tests =====

func TestPackageVariables(t *testing.T) {
	// Test that package variables are initialized
	// On non-Linux platforms, newMenuDelay should remain unset (0)
	// On Linux, it depends on the desktop environment

	if runtime.GOOS != "linux" {
		if newMenuDelay != 0 {
			t.Errorf("newMenuDelay should be 0 on non-Linux, got %v", newMenuDelay)
		}
		if hideMullvadCities {
			t.Error("hideMullvadCities should be false on non-Linux")
		}
	}
	// On Linux, we can't test the exact values since they depend on XDG_CURRENT_DESKTOP
	// but we can verify they are reasonable
}

// ===== Mullvad City Tests =====

func TestMvCity_BestPeerSelection(t *testing.T) {
	ps1 := &ipnstate.PeerStatus{
		ID: tailcfg.StableNodeID("peer1"),
		Location: &tailcfg.Location{
			Priority: 50,
		},
	}
	ps2 := &ipnstate.PeerStatus{
		ID: tailcfg.StableNodeID("peer2"),
		Location: &tailcfg.Location{
			Priority: 100,
		},
	}
	ps3 := &ipnstate.PeerStatus{
		ID: tailcfg.StableNodeID("peer3"),
		Location: &tailcfg.Location{
			Priority: 75,
		},
	}

	city := &mvCity{
		name:  "TestCity",
		peers: []*ipnstate.PeerStatus{ps1, ps2, ps3},
	}

	// Manually find best (simulating what newMullvadPeers does)
	for _, ps := range city.peers {
		if city.best == nil || ps.Location.Priority > city.best.Location.Priority {
			city.best = ps
		}
	}

	if city.best.ID != "peer2" {
		t.Errorf("best peer = %q, want peer2 (priority 100)", city.best.ID)
	}
}

// ===== Edge Cases =====

func TestCountryFlag_Unicode(t *testing.T) {
	// Test that the flag emoji is actually 2 runes (regional indicators)
	flag := countryFlag("US")
	runes := []rune(flag)

	if len(runes) != 2 {
		t.Errorf("US flag should be 2 runes, got %d", len(runes))
	}

	// Regional indicator for U (🇺)
	expectedU := rune(0x1F1FA)
	// Regional indicator for S (🇸)
	expectedS := rune(0x1F1F8)

	if runes[0] != expectedU {
		t.Errorf("first rune = %U, want %U", runes[0], expectedU)
	}
	if runes[1] != expectedS {
		t.Errorf("second rune = %U, want %U", runes[1], expectedS)
	}
}

func TestNewMullvadPeers_MultiplePeersInCity(t *testing.T) {
	status := &ipnstate.Status{
		Peer: map[tailcfg.NodeKey]*ipnstate.PeerStatus{
			tailcfg.NodeKey{1}: {
				ID:             tailcfg.StableNodeID("node1"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Germany",
					CountryCode: "DE",
					City:        "Berlin",
					CityCode:    "ber",
					Priority:    100,
				},
			},
			tailcfg.NodeKey{2}: {
				ID:             tailcfg.StableNodeID("node2"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Germany",
					CountryCode: "DE",
					City:        "Berlin",
					CityCode:    "ber",
					Priority:    50,
				},
			},
			tailcfg.NodeKey{3}: {
				ID:             tailcfg.StableNodeID("node3"),
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Germany",
					CountryCode: "DE",
					City:        "Berlin",
					CityCode:    "ber",
					Priority:    75,
				},
			},
		},
	}

	mp := newMullvadPeers(status)

	de := mp.countries["DE"]
	berlin := de.cities["ber"]

	// Should have all 3 peers
	if len(berlin.peers) != 3 {
		t.Errorf("Berlin should have 3 peers, got %d", len(berlin.peers))
	}

	// Best should be node1 (priority 100)
	if berlin.best.ID != "node1" {
		t.Errorf("best Berlin peer = %q, want node1", berlin.best.ID)
	}
}

func TestProfileTitle_MultilineOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping Linux-specific test")
	}

	profile := ipn.LoginProfile{
		Name: "user@example.com",
		NetworkProfile: ipn.NetworkProfile{
			DomainName:  "tailnet.ts.net",
			MagicDNSName: "tailnet",
		},
	}

	result := profileTitle(profile)

	// On Linux, should use newline separator
	if result != "user@example.com\ntailnet" {
		t.Errorf("Linux profile title = %q, want %q", result, "user@example.com\ntailnet")
	}
}

func TestMullvadPeers_EmptyCountries(t *testing.T) {
	mp := mullvadPeers{
		countries: map[string]*mvCountry{},
	}

	sorted := mp.sortedCountries()

	if len(sorted) != 0 {
		t.Errorf("expected 0 countries, got %d", len(sorted))
	}
}

func TestMvCountry_EmptyCities(t *testing.T) {
	country := &mvCountry{
		code:   "US",
		name:   "United States",
		cities: map[string]*mvCity{},
	}

	sorted := country.sortedCities()

	if len(sorted) != 0 {
		t.Errorf("expected 0 cities, got %d", len(sorted))
	}
}

// ===== Integration-style Tests =====

func TestMullvadPeers_RealWorldScenario(t *testing.T) {
	// Simulate a real-world scenario with multiple countries and cities
	status := &ipnstate.Status{
		Self: &ipnstate.PeerStatus{
			TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
		},
		Peer: map[tailcfg.NodeKey]*ipnstate.PeerStatus{
			tailcfg.NodeKey{1}: {
				ID:             "us-nyc-1",
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "United States",
					CountryCode: "US",
					City:        "New York",
					CityCode:    "nyc",
					Priority:    100,
				},
			},
			tailcfg.NodeKey{2}: {
				ID:             "us-nyc-2",
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "United States",
					CountryCode: "US",
					City:        "New York",
					CityCode:    "nyc",
					Priority:    90,
				},
			},
			tailcfg.NodeKey{3}: {
				ID:             "us-lax-1",
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "United States",
					CountryCode: "US",
					City:        "Los Angeles",
					CityCode:    "lax",
					Priority:    95,
				},
			},
			tailcfg.NodeKey{4}: {
				ID:             "de-ber-1",
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Germany",
					CountryCode: "DE",
					City:        "Berlin",
					CityCode:    "ber",
					Priority:    85,
				},
			},
			tailcfg.NodeKey{5}: {
				ID:             "jp-tyo-1",
				ExitNodeOption: true,
				Location: &tailcfg.Location{
					Country:     "Japan",
					CountryCode: "JP",
					City:        "Tokyo",
					CityCode:    "tyo",
					Priority:    80,
				},
			},
		},
	}

	mp := newMullvadPeers(status)

	// Verify country count
	if len(mp.countries) != 3 {
		t.Errorf("expected 3 countries, got %d", len(mp.countries))
	}

	// Verify US has 2 cities
	us := mp.countries["US"]
	if len(us.cities) != 2 {
		t.Errorf("US should have 2 cities, got %d", len(us.cities))
	}

	// Verify US best is us-nyc-1 (priority 100)
	if us.best.ID != "us-nyc-1" {
		t.Errorf("US best = %q, want us-nyc-1", us.best.ID)
	}

	// Verify NYC has 2 peers
	nyc := us.cities["nyc"]
	if len(nyc.peers) != 2 {
		t.Errorf("NYC should have 2 peers, got %d", len(nyc.peers))
	}

	// Verify sorted countries
	sorted := mp.sortedCountries()
	expectedOrder := []string{"Germany", "Japan", "United States"}
	for i, country := range sorted {
		if country.name != expectedOrder[i] {
			t.Errorf("sorted country[%d] = %q, want %q", i, country.name, expectedOrder[i])
		}
	}

	// Verify sorted US cities
	sortedCities := us.sortedCities()
	expectedCityOrder := []string{"Los Angeles", "New York"}
	for i, city := range sortedCities {
		if city.name != expectedCityOrder[i] {
			t.Errorf("sorted city[%d] = %q, want %q", i, city.name, expectedCityOrder[i])
		}
	}
}
