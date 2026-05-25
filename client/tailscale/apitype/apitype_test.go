// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package apitype

import (
	"encoding/json"
	"testing"

	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

func TestLocalAPIHost_Constant(t *testing.T) {
	if LocalAPIHost != "local-tailscaled.sock" {
		t.Errorf("LocalAPIHost = %q, want %q", LocalAPIHost, "local-tailscaled.sock")
	}
}

func TestWhoIsResponse_JSON(t *testing.T) {
	tests := []struct {
		name string
		resp WhoIsResponse
	}{
		{
			name: "basic",
			resp: WhoIsResponse{
				Node: &tailcfg.Node{
					ID: 123,
				},
				UserProfile: &tailcfg.UserProfile{
					ID:          456,
					LoginName:   "user@example.com",
					DisplayName: "Test User",
				},
				CapMap: tailcfg.PeerCapMap{},
			},
		},
		{
			name: "with_capabilities",
			resp: WhoIsResponse{
				Node: &tailcfg.Node{
					ID: 123,
				},
				UserProfile: &tailcfg.UserProfile{
					ID:        456,
					LoginName: "user@example.com",
				},
				CapMap: tailcfg.PeerCapMap{
					"cap:test": []tailcfg.RawMessage{
						tailcfg.RawMessage(`{"key":"value"}`),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			data, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			// Unmarshal
			var decoded WhoIsResponse
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			// Verify round-trip
			if decoded.Node.ID != tt.resp.Node.ID {
				t.Errorf("Node.ID = %v, want %v", decoded.Node.ID, tt.resp.Node.ID)
			}
			if decoded.UserProfile.ID != tt.resp.UserProfile.ID {
				t.Errorf("UserProfile.ID = %v, want %v", decoded.UserProfile.ID, tt.resp.UserProfile.ID)
			}
		})
	}
}

func TestFileTarget_JSON(t *testing.T) {
	ft := FileTarget{
		Node: &tailcfg.Node{
			ID:   123,
			Name: "test-node",
		},
		PeerAPIURL: "http://100.64.0.1:12345",
	}

	data, err := json.Marshal(ft)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded FileTarget
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if decoded.PeerAPIURL != ft.PeerAPIURL {
		t.Errorf("PeerAPIURL = %q, want %q", decoded.PeerAPIURL, ft.PeerAPIURL)
	}
	if decoded.Node.ID != ft.Node.ID {
		t.Errorf("Node.ID = %v, want %v", decoded.Node.ID, ft.Node.ID)
	}
}

func TestWaitingFile_JSON(t *testing.T) {
	tests := []struct {
		name string
		wf   WaitingFile
	}{
		{
			name: "small_file",
			wf: WaitingFile{
				Name: "document.pdf",
				Size: 1024,
			},
		},
		{
			name: "large_file",
			wf: WaitingFile{
				Name: "video.mp4",
				Size: 1024 * 1024 * 1024,
			},
		},
		{
			name: "zero_size",
			wf: WaitingFile{
				Name: "empty.txt",
				Size: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.wf)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			var decoded WaitingFile
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if decoded.Name != tt.wf.Name {
				t.Errorf("Name = %q, want %q", decoded.Name, tt.wf.Name)
			}
			if decoded.Size != tt.wf.Size {
				t.Errorf("Size = %d, want %d", decoded.Size, tt.wf.Size)
			}
		})
	}
}

func TestSetPushDeviceTokenRequest_JSON(t *testing.T) {
	req := SetPushDeviceTokenRequest{
		PushDeviceToken: "test-token-123",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded SetPushDeviceTokenRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if decoded.PushDeviceToken != req.PushDeviceToken {
		t.Errorf("PushDeviceToken = %q, want %q", decoded.PushDeviceToken, req.PushDeviceToken)
	}
}

func TestReloadConfigResponse_JSON(t *testing.T) {
	tests := []struct {
		name string
		resp ReloadConfigResponse
	}{
		{
			name: "success",
			resp: ReloadConfigResponse{
				Reloaded: true,
				Err:      "",
			},
		},
		{
			name: "error",
			resp: ReloadConfigResponse{
				Reloaded: false,
				Err:      "failed to reload config",
			},
		},
		{
			name: "not_in_config_mode",
			resp: ReloadConfigResponse{
				Reloaded: false,
				Err:      "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			var decoded ReloadConfigResponse
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if decoded.Reloaded != tt.resp.Reloaded {
				t.Errorf("Reloaded = %v, want %v", decoded.Reloaded, tt.resp.Reloaded)
			}
			if decoded.Err != tt.resp.Err {
				t.Errorf("Err = %q, want %q", decoded.Err, tt.resp.Err)
			}
		})
	}
}

func TestExitNodeSuggestionResponse_JSON(t *testing.T) {
	resp := ExitNodeSuggestionResponse{
		ID:   "stable-node-id-123",
		Name: "exit-node-1",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded ExitNodeSuggestionResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if decoded.ID != resp.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, resp.ID)
	}
	if decoded.Name != resp.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, resp.Name)
	}
}

func TestDNSOSConfig_JSON(t *testing.T) {
	cfg := DNSOSConfig{
		Nameservers:   []string{"8.8.8.8", "1.1.1.1"},
		SearchDomains: []string{"example.com", "local"},
		MatchDomains:  []string{"*.example.com"},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded DNSOSConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if len(decoded.Nameservers) != len(cfg.Nameservers) {
		t.Errorf("Nameservers length = %d, want %d", len(decoded.Nameservers), len(cfg.Nameservers))
	}
	if len(decoded.SearchDomains) != len(cfg.SearchDomains) {
		t.Errorf("SearchDomains length = %d, want %d", len(decoded.SearchDomains), len(cfg.SearchDomains))
	}
	if len(decoded.MatchDomains) != len(cfg.MatchDomains) {
		t.Errorf("MatchDomains length = %d, want %d", len(decoded.MatchDomains), len(cfg.MatchDomains))
	}
}

func TestDNSQueryResponse_JSON(t *testing.T) {
	resp := DNSQueryResponse{
		Bytes: []byte{1, 2, 3, 4, 5},
		Resolvers: []*dnstype.Resolver{
			{Addr: "8.8.8.8"},
			{Addr: "1.1.1.1"},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded DNSQueryResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if len(decoded.Bytes) != len(resp.Bytes) {
		t.Errorf("Bytes length = %d, want %d", len(decoded.Bytes), len(resp.Bytes))
	}
	if len(decoded.Resolvers) != len(resp.Resolvers) {
		t.Errorf("Resolvers length = %d, want %d", len(decoded.Resolvers), len(resp.Resolvers))
	}
}

func TestDNSConfig_JSON(t *testing.T) {
	cfg := DNSConfig{
		Resolvers: []DNSResolver{
			{Addr: "8.8.8.8"},
			{Addr: "1.1.1.1", BootstrapResolution: []string{"1.1.1.1"}},
		},
		FallbackResolvers: []DNSResolver{
			{Addr: "9.9.9.9"},
		},
		Routes: map[string][]DNSResolver{
			"example.com": {
				{Addr: "10.0.0.1"},
			},
		},
		Domains:     []string{"example.com"},
		Nameservers: []string{"8.8.8.8"},
		Proxied:     true,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal() failed: %v", err)
	}

	var decoded DNSConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}

	if len(decoded.Resolvers) != len(cfg.Resolvers) {
		t.Errorf("Resolvers length = %d, want %d", len(decoded.Resolvers), len(cfg.Resolvers))
	}
	if len(decoded.FallbackResolvers) != len(cfg.FallbackResolvers) {
		t.Errorf("FallbackResolvers length = %d, want %d", len(decoded.FallbackResolvers), len(cfg.FallbackResolvers))
	}
	if len(decoded.Routes) != len(cfg.Routes) {
		t.Errorf("Routes length = %d, want %d", len(decoded.Routes), len(cfg.Routes))
	}
	if decoded.Proxied != cfg.Proxied {
		t.Errorf("Proxied = %v, want %v", decoded.Proxied, cfg.Proxied)
	}
}

func TestDNSResolver_JSON(t *testing.T) {
	tests := []struct {
		name string
		r    DNSResolver
	}{
		{
			name: "simple",
			r: DNSResolver{
				Addr: "8.8.8.8",
			},
		},
		{
			name: "with_bootstrap",
			r: DNSResolver{
				Addr:                "dns.google",
				BootstrapResolution: []string{"8.8.8.8", "8.8.4.4"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.r)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			var decoded DNSResolver
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}

			if decoded.Addr != tt.r.Addr {
				t.Errorf("Addr = %q, want %q", decoded.Addr, tt.r.Addr)
			}
			if len(decoded.BootstrapResolution) != len(tt.r.BootstrapResolution) {
				t.Errorf("BootstrapResolution length = %d, want %d",
					len(decoded.BootstrapResolution), len(tt.r.BootstrapResolution))
			}
		})
	}
}

// Test empty structures serialize correctly
func TestEmptyStructures_JSON(t *testing.T) {
	tests := []struct {
		name string
		v    any
	}{
		{"WhoIsResponse", WhoIsResponse{}},
		{"FileTarget", FileTarget{}},
		{"WaitingFile", WaitingFile{}},
		{"SetPushDeviceTokenRequest", SetPushDeviceTokenRequest{}},
		{"ReloadConfigResponse", ReloadConfigResponse{}},
		{"ExitNodeSuggestionResponse", ExitNodeSuggestionResponse{}},
		{"DNSOSConfig", DNSOSConfig{}},
		{"DNSQueryResponse", DNSQueryResponse{}},
		{"DNSConfig", DNSConfig{}},
		{"DNSResolver", DNSResolver{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.v)
			if err != nil {
				t.Fatalf("Marshal() failed: %v", err)
			}

			// Verify it produces valid JSON
			var result map[string]any
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatalf("Unmarshal() to map failed: %v", err)
			}
		})
	}
}
