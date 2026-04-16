// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipn

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
	"tailscale.com/types/preftype"
)

// TestConfigVAlpha_ToPrefs_Nil tests nil config handling
func TestConfigVAlpha_ToPrefs_Nil(t *testing.T) {
	var c *ConfigVAlpha
	mp, err := c.ToPrefs()
	if err != nil {
		t.Errorf("ToPrefs() with nil config should not error: %v", err)
	}

	// Nil config should produce empty MaskedPrefs
	if mp.WantRunningSet {
		t.Error("nil config should not set WantRunningSet")
	}
	if mp.ControlURLSet {
		t.Error("nil config should not set ControlURLSet")
	}
}

// TestConfigVAlpha_ToPrefs_Empty tests empty config
func TestConfigVAlpha_ToPrefs_Empty(t *testing.T) {
	c := &ConfigVAlpha{}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Errorf("ToPrefs() with empty config failed: %v", err)
	}

	// Empty config should still set AdvertiseServicesSet
	if !mp.AdvertiseServicesSet {
		t.Error("AdvertiseServicesSet should be true even for empty config")
	}
}

// TestConfigVAlpha_ToPrefs_WantRunning tests Enabled field
func TestConfigVAlpha_ToPrefs_WantRunning(t *testing.T) {
	tests := []struct {
		name           string
		enabled        opt.Bool
		wantRunning    bool
		wantRunningSet bool
	}{
		{
			name:           "enabled_true",
			enabled:        "true",
			wantRunning:    true,
			wantRunningSet: true,
		},
		{
			name:           "enabled_false",
			enabled:        "false",
			wantRunning:    false,
			wantRunningSet: true,
		},
		{
			name:           "enabled_unset",
			enabled:        "",
			wantRunning:    true, // defaults to true when unset
			wantRunningSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				Enabled: tt.enabled,
			}
			mp, err := c.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() failed: %v", err)
			}

			if mp.WantRunning != tt.wantRunning {
				t.Errorf("WantRunning = %v, want %v", mp.WantRunning, tt.wantRunning)
			}
			if mp.WantRunningSet != tt.wantRunningSet {
				t.Errorf("WantRunningSet = %v, want %v", mp.WantRunningSet, tt.wantRunningSet)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_ServerURL tests ServerURL field
func TestConfigVAlpha_ToPrefs_ServerURL(t *testing.T) {
	tests := []struct {
		name      string
		serverURL *string
		wantURL   string
		wantSet   bool
	}{
		{
			name:      "custom_server",
			serverURL: stringPtr("https://custom.example.com"),
			wantURL:   "https://custom.example.com",
			wantSet:   true,
		},
		{
			name:      "nil_server",
			serverURL: nil,
			wantURL:   "",
			wantSet:   false,
		},
		{
			name:      "empty_server",
			serverURL: stringPtr(""),
			wantURL:   "",
			wantSet:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				ServerURL: tt.serverURL,
			}
			mp, err := c.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() failed: %v", err)
			}

			if mp.ControlURL != tt.wantURL {
				t.Errorf("ControlURL = %q, want %q", mp.ControlURL, tt.wantURL)
			}
			if mp.ControlURLSet != tt.wantSet {
				t.Errorf("ControlURLSet = %v, want %v", mp.ControlURLSet, tt.wantSet)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_AuthKey tests AuthKey field
func TestConfigVAlpha_ToPrefs_AuthKey(t *testing.T) {
	tests := []struct {
		name          string
		authKey       *string
		wantLoggedOut bool
		wantSet       bool
	}{
		{
			name:          "with_authkey",
			authKey:       stringPtr("tskey-auth-xxx"),
			wantLoggedOut: false,
			wantSet:       true,
		},
		{
			name:          "empty_authkey",
			authKey:       stringPtr(""),
			wantLoggedOut: false,
			wantSet:       false,
		},
		{
			name:          "nil_authkey",
			authKey:       nil,
			wantLoggedOut: false,
			wantSet:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				AuthKey: tt.authKey,
			}
			mp, err := c.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() failed: %v", err)
			}

			if mp.LoggedOut != tt.wantLoggedOut {
				t.Errorf("LoggedOut = %v, want %v", mp.LoggedOut, tt.wantLoggedOut)
			}
			if mp.LoggedOutSet != tt.wantSet {
				t.Errorf("LoggedOutSet = %v, want %v", mp.LoggedOutSet, tt.wantSet)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_OperatorUser tests OperatorUser field
func TestConfigVAlpha_ToPrefs_OperatorUser(t *testing.T) {
	user := "alice"
	c := &ConfigVAlpha{
		OperatorUser: &user,
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	if mp.OperatorUser != user {
		t.Errorf("OperatorUser = %q, want %q", mp.OperatorUser, user)
	}
	if !mp.OperatorUserSet {
		t.Error("OperatorUserSet should be true")
	}
}

// TestConfigVAlpha_ToPrefs_Hostname tests Hostname field
func TestConfigVAlpha_ToPrefs_Hostname(t *testing.T) {
	hostname := "my-machine"
	c := &ConfigVAlpha{
		Hostname: &hostname,
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	if mp.Hostname != hostname {
		t.Errorf("Hostname = %q, want %q", mp.Hostname, hostname)
	}
	if !mp.HostnameSet {
		t.Error("HostnameSet should be true")
	}
}

// TestConfigVAlpha_ToPrefs_DNS tests AcceptDNS field
func TestConfigVAlpha_ToPrefs_DNS(t *testing.T) {
	tests := []struct {
		name        string
		acceptDNS   opt.Bool
		wantCorpDNS bool
		wantSet     bool
	}{
		{
			name:        "accept_dns_true",
			acceptDNS:   "true",
			wantCorpDNS: true,
			wantSet:     true,
		},
		{
			name:        "accept_dns_false",
			acceptDNS:   "false",
			wantCorpDNS: false,
			wantSet:     true,
		},
		{
			name:        "accept_dns_unset",
			acceptDNS:   "",
			wantCorpDNS: false,
			wantSet:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				AcceptDNS: tt.acceptDNS,
			}
			mp, err := c.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() failed: %v", err)
			}

			if mp.CorpDNS != tt.wantCorpDNS {
				t.Errorf("CorpDNS = %v, want %v", mp.CorpDNS, tt.wantCorpDNS)
			}
			if mp.CorpDNSSet != tt.wantSet {
				t.Errorf("CorpDNSSet = %v, want %v", mp.CorpDNSSet, tt.wantSet)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_Routes tests AcceptRoutes field
func TestConfigVAlpha_ToPrefs_Routes(t *testing.T) {
	tests := []struct {
		name          string
		acceptRoutes  opt.Bool
		wantRouteAll  bool
		wantRouteSet bool
	}{
		{
			name:          "accept_routes_true",
			acceptRoutes:  "true",
			wantRouteAll:  true,
			wantRouteSet: true,
		},
		{
			name:          "accept_routes_false",
			acceptRoutes:  "false",
			wantRouteAll:  false,
			wantRouteSet: true,
		},
		{
			name:          "accept_routes_unset",
			acceptRoutes:  "",
			wantRouteAll:  false,
			wantRouteSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				AcceptRoutes: tt.acceptRoutes,
			}
			mp, err := c.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() failed: %v", err)
			}

			if mp.RouteAll != tt.wantRouteAll {
				t.Errorf("RouteAll = %v, want %v", mp.RouteAll, tt.wantRouteAll)
			}
			if mp.RouteAllSet != tt.wantRouteSet {
				t.Errorf("RouteAllSet = %v, want %v", mp.RouteAllSet, tt.wantRouteSet)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_ExitNode tests ExitNode field
func TestConfigVAlpha_ToPrefs_ExitNode(t *testing.T) {
	tests := []struct {
		name         string
		exitNode     *string
		wantIP       netip.Addr
		wantIPSet    bool
		wantID       tailcfg.StableNodeID
		wantIDSet    bool
	}{
		{
			name:      "exit_node_ip",
			exitNode:  stringPtr("100.64.0.1"),
			wantIP:    netip.MustParseAddr("100.64.0.1"),
			wantIPSet: true,
			wantIDSet: false,
		},
		{
			name:      "exit_node_stable_id",
			exitNode:  stringPtr("node-abc123"),
			wantID:    "node-abc123",
			wantIDSet: true,
			wantIPSet: false,
		},
		{
			name:      "exit_node_nil",
			exitNode:  nil,
			wantIPSet: false,
			wantIDSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				ExitNode: tt.exitNode,
			}
			mp, err := c.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() failed: %v", err)
			}

			if mp.ExitNodeIPSet != tt.wantIPSet {
				t.Errorf("ExitNodeIPSet = %v, want %v", mp.ExitNodeIPSet, tt.wantIPSet)
			}
			if tt.wantIPSet && mp.ExitNodeIP != tt.wantIP {
				t.Errorf("ExitNodeIP = %v, want %v", mp.ExitNodeIP, tt.wantIP)
			}

			if mp.ExitNodeIDSet != tt.wantIDSet {
				t.Errorf("ExitNodeIDSet = %v, want %v", mp.ExitNodeIDSet, tt.wantIDSet)
			}
			if tt.wantIDSet && mp.ExitNodeID != tt.wantID {
				t.Errorf("ExitNodeID = %v, want %v", mp.ExitNodeID, tt.wantID)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_AllowLANWhileUsingExitNode tests the field
func TestConfigVAlpha_ToPrefs_AllowLANWhileUsingExitNode(t *testing.T) {
	c := &ConfigVAlpha{
		AllowLANWhileUsingExitNode: "true",
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	if !mp.ExitNodeAllowLANAccess {
		t.Error("ExitNodeAllowLANAccess should be true")
	}
	if !mp.ExitNodeAllowLANAccessSet {
		t.Error("ExitNodeAllowLANAccessSet should be true")
	}
}

// TestConfigVAlpha_ToPrefs_AdvertiseRoutes tests AdvertiseRoutes field
func TestConfigVAlpha_ToPrefs_AdvertiseRoutes(t *testing.T) {
	routes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}

	c := &ConfigVAlpha{
		AdvertiseRoutes: routes,
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	if !mp.AdvertiseRoutesSet {
		t.Error("AdvertiseRoutesSet should be true")
	}
	if len(mp.AdvertiseRoutes) != 2 {
		t.Errorf("AdvertiseRoutes length = %d, want 2", len(mp.AdvertiseRoutes))
	}
}

// TestConfigVAlpha_ToPrefs_NetfilterMode tests NetfilterMode field
func TestConfigVAlpha_ToPrefs_NetfilterMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    *string
		wantErr bool
		wantSet bool
	}{
		{
			name:    "mode_on",
			mode:    stringPtr("on"),
			wantErr: false,
			wantSet: true,
		},
		{
			name:    "mode_off",
			mode:    stringPtr("off"),
			wantErr: false,
			wantSet: true,
		},
		{
			name:    "mode_nodivert",
			mode:    stringPtr("nodivert"),
			wantErr: false,
			wantSet: true,
		},
		{
			name:    "invalid_mode",
			mode:    stringPtr("invalid"),
			wantErr: true,
			wantSet: false,
		},
		{
			name:    "nil_mode",
			mode:    nil,
			wantErr: false,
			wantSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				NetfilterMode: tt.mode,
			}
			mp, err := c.ToPrefs()

			if tt.wantErr && err == nil {
				t.Error("expected error for invalid NetfilterMode")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tt.wantErr && mp.NetfilterModeSet != tt.wantSet {
				t.Errorf("NetfilterModeSet = %v, want %v", mp.NetfilterModeSet, tt.wantSet)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_BooleanFlags tests various boolean flags
func TestConfigVAlpha_ToPrefs_BooleanFlags(t *testing.T) {
	c := &ConfigVAlpha{
		PostureChecking: "true",
		RunSSHServer:    "true",
		RunWebClient:    "false",
		ShieldsUp:       "true",
		DisableSNAT:     "true",
		NoStatefulFiltering: "true",
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	if !mp.PostureChecking {
		t.Error("PostureChecking should be true")
	}
	if !mp.PostureCheckingSet {
		t.Error("PostureCheckingSet should be true")
	}

	if !mp.RunSSH {
		t.Error("RunSSH should be true")
	}
	if !mp.RunSSHSet {
		t.Error("RunSSHSet should be true")
	}

	if mp.RunWebClient {
		t.Error("RunWebClient should be false")
	}
	if !mp.RunWebClientSet {
		t.Error("RunWebClientSet should be true")
	}

	if !mp.ShieldsUp {
		t.Error("ShieldsUp should be true")
	}
	if !mp.ShieldsUpSet {
		t.Error("ShieldsUpSet should be true")
	}

	if !mp.NoSNAT {
		t.Error("NoSNAT should be true")
	}
}

// TestConfigVAlpha_ToPrefs_AdvertiseServices tests AdvertiseServices field
func TestConfigVAlpha_ToPrefs_AdvertiseServices(t *testing.T) {
	tests := []struct {
		name     string
		services []string
		wantLen  int
	}{
		{
			name:     "multiple_services",
			services: []string{"service1", "service2", "service3"},
			wantLen:  3,
		},
		{
			name:     "single_service",
			services: []string{"service1"},
			wantLen:  1,
		},
		{
			name:     "empty_services",
			services: []string{},
			wantLen:  0,
		},
		{
			name:     "nil_services",
			services: nil,
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ConfigVAlpha{
				AdvertiseServices: tt.services,
			}
			mp, err := c.ToPrefs()
			if err != nil {
				t.Fatalf("ToPrefs() failed: %v", err)
			}

			// AdvertiseServicesSet should always be true
			if !mp.AdvertiseServicesSet {
				t.Error("AdvertiseServicesSet should always be true")
			}

			if len(mp.AdvertiseServices) != tt.wantLen {
				t.Errorf("AdvertiseServices length = %d, want %d", len(mp.AdvertiseServices), tt.wantLen)
			}
		})
	}
}

// TestConfigVAlpha_ToPrefs_AutoUpdate tests AutoUpdate field
func TestConfigVAlpha_ToPrefs_AutoUpdate(t *testing.T) {
	c := &ConfigVAlpha{
		AutoUpdate: &AutoUpdatePrefs{
			Apply: opt.NewBool(true),
			Check: opt.NewBool(true),
		},
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	if !mp.AutoUpdateSet.ApplySet {
		t.Error("AutoUpdateSet.ApplySet should be true")
	}
	if !mp.AutoUpdateSet.CheckSet {
		t.Error("AutoUpdateSet.CheckSet should be true")
	}
}

// TestConfigVAlpha_ToPrefs_AppConnector tests AppConnector field
func TestConfigVAlpha_ToPrefs_AppConnector(t *testing.T) {
	c := &ConfigVAlpha{
		AppConnector: &AppConnectorPrefs{
			Advertise: true,
		},
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	if !mp.AppConnectorSet {
		t.Error("AppConnectorSet should be true")
	}
	if !mp.AppConnector.Advertise {
		t.Error("AppConnector.Advertise should be true")
	}
}

// TestConfigVAlpha_ToPrefs_StaticEndpoints tests StaticEndpoints field
func TestConfigVAlpha_ToPrefs_StaticEndpoints(t *testing.T) {
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("1.2.3.4:5678"),
		netip.MustParseAddrPort("[::1]:9999"),
	}

	c := &ConfigVAlpha{
		StaticEndpoints: endpoints,
	}
	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	// Note: StaticEndpoints might not be directly set in MaskedPrefs
	// This test verifies the config accepts the field
	_ = mp
}

// TestConfigVAlpha_ToPrefs_ComplexConfig tests a fully populated config
func TestConfigVAlpha_ToPrefs_ComplexConfig(t *testing.T) {
	serverURL := "https://custom.example.com"
	authKey := "tskey-auth-xxx"
	operator := "alice"
	hostname := "my-machine"
	exitNode := "100.64.0.1"
	mode := "on"

	c := &ConfigVAlpha{
		Version:                    "alpha0",
		Locked:                     "true",
		ServerURL:                  &serverURL,
		AuthKey:                    &authKey,
		Enabled:                    "true",
		OperatorUser:               &operator,
		Hostname:                   &hostname,
		AcceptDNS:                  "true",
		AcceptRoutes:               "true",
		ExitNode:                   &exitNode,
		AllowLANWhileUsingExitNode: "true",
		AdvertiseRoutes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/24"),
		},
		DisableSNAT:         "false",
		AdvertiseServices:   []string{"service1", "service2"},
		NetfilterMode:       &mode,
		NoStatefulFiltering: "false",
		PostureChecking:     "true",
		RunSSHServer:        "true",
		RunWebClient:        "false",
		ShieldsUp:           "false",
		AppConnector: &AppConnectorPrefs{
			Advertise: true,
		},
		AutoUpdate: &AutoUpdatePrefs{
			Apply: opt.NewBool(true),
			Check: opt.NewBool(true),
		},
	}

	mp, err := c.ToPrefs()
	if err != nil {
		t.Fatalf("ToPrefs() failed: %v", err)
	}

	// Verify critical fields are set
	if !mp.WantRunning {
		t.Error("WantRunning should be true")
	}
	if mp.ControlURL != serverURL {
		t.Errorf("ControlURL = %q, want %q", mp.ControlURL, serverURL)
	}
	if mp.OperatorUser != operator {
		t.Errorf("OperatorUser = %q, want %q", mp.OperatorUser, operator)
	}
	if mp.Hostname != hostname {
		t.Errorf("Hostname = %q, want %q", mp.Hostname, hostname)
	}
	if !mp.CorpDNS {
		t.Error("CorpDNS should be true")
	}
	if !mp.RouteAll {
		t.Error("RouteAll should be true")
	}
	if len(mp.AdvertiseRoutes) != 1 {
		t.Errorf("AdvertiseRoutes length = %d, want 1", len(mp.AdvertiseRoutes))
	}
	if len(mp.AdvertiseServices) != 2 {
		t.Errorf("AdvertiseServices length = %d, want 2", len(mp.AdvertiseServices))
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
