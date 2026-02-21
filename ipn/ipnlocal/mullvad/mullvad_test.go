// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mullvad

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestIsValidAccountNumber(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"valid", "1234567890123456", true},
		{"too short", "12345678901234", false},
		{"too long", "12345678901234567", false},
		{"empty", "", false},
		{"with letters", "123456789012345a", false},
		{"with spaces", "1234567890123 56", false},
		{"with dashes", "1234-5678-9012-3456", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidAccountNumber(tt.input)
			if got != tt.want {
				t.Errorf("isValidAccountNumber(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	// Note: This test requires TS_ENABLE_CUSTOM_MULLVAD=1 to pass
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "1")

	tests := []struct {
		name      string
		account   string
		wantErr   error
		wantNil   bool
	}{
		{"valid account", "1234567890123456", nil, false},
		{"invalid account short", "123456", ErrInvalidAccount, true},
		{"invalid account letters", "abcdef1234567890", ErrInvalidAccount, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.account, logger.Discard, nil, nil)
			if err != tt.wantErr {
				t.Errorf("NewClient() error = %v, want %v", err, tt.wantErr)
			}
			if (c == nil) != tt.wantNil {
				t.Errorf("NewClient() returned nil = %v, want %v", c == nil, tt.wantNil)
			}
		})
	}
}

func TestNewClientFeatureDisabled(t *testing.T) {
	// Ensure the feature is disabled
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "")

	_, err := NewClient("1234567890123456", logger.Discard, nil, nil)
	if err != ErrNotEnabled {
		t.Errorf("NewClient() error = %v, want %v", err, ErrNotEnabled)
	}
}

func TestMaskedAccountNumber(t *testing.T) {
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "1")

	c, err := NewClient("1234567890123456", logger.Discard, nil, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	masked := c.MaskedAccountNumber()
	expected := "1234********3456"
	if masked != expected {
		t.Errorf("MaskedAccountNumber() = %q, want %q", masked, expected)
	}
}

// Mock server for testing API calls
type mockMullvadServer struct {
	t            *testing.T
	accountToken string
	expiry       time.Time
	devices      []deviceResponse
	servers      []relayResponse
}

func (m *mockMullvadServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == "POST" && r.URL.Path == "/auth/v1/token":
		// Token endpoint
		var req struct {
			AccountNumber string `json:"account_number"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.AccountNumber != "1234567890123456" {
			http.Error(w, "invalid account", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "test-token-" + req.AccountNumber,
			Expiry:      time.Now().Add(24 * time.Hour),
		})

	case r.Method == "GET" && r.URL.Path == "/public/accounts/v1/1234567890123456":
		// Account status endpoint
		json.NewEncoder(w).Encode(accountResponse{
			Expiry: m.expiry,
		})

	case r.Method == "GET" && r.URL.Path == "/public/accounts/v1/0000000000000000":
		// Invalid account
		http.Error(w, "not found", http.StatusNotFound)

	case r.Method == "GET" && r.URL.Path == "/accounts/v1/devices":
		// List devices
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(m.devices)

	case r.Method == "POST" && r.URL.Path == "/accounts/v1/devices":
		// Register device
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req struct {
			Pubkey    string `json:"pubkey"`
			HijackDNS bool   `json:"hijack_dns"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := deviceResponse{
			ID:          "test-device-id",
			Pubkey:      req.Pubkey,
			IPv4Address: "10.64.0.1/32",
			IPv6Address: "fc00:bbbb:bbbb:bb01::1/128",
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)

	case r.URL.Path == "/public/relays/wireguard/v2/":
		// Server list - return in the proper relayListResponse format
		resp := relayListResponse{
			Locations: map[string]locationInfo{
				"us-nyc": {Country: "USA", City: "New York City"},
				"de-fra": {Country: "Germany", City: "Frankfurt"},
			},
		}
		resp.WireGuard.Relays = m.servers
		json.NewEncoder(w).Encode(resp)

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func TestAuthenticate(t *testing.T) {
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "1")

	mock := &mockMullvadServer{
		t:      t,
		expiry: time.Now().Add(30 * 24 * time.Hour),
	}
	server := httptest.NewServer(mock)
	defer server.Close()

	c, err := NewClient("1234567890123456", t.Logf, nil, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c.apiBase = server.URL

	ctx := context.Background()
	if err := c.Authenticate(ctx); err != nil {
		t.Errorf("Authenticate() error = %v", err)
	}
}

func TestGetAccountStatus(t *testing.T) {
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "1")

	expiry := time.Now().Add(30 * 24 * time.Hour)
	mock := &mockMullvadServer{
		t:      t,
		expiry: expiry,
	}
	server := httptest.NewServer(mock)
	defer server.Close()

	c, err := NewClient("1234567890123456", t.Logf, nil, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c.apiBase = server.URL

	ctx := context.Background()
	status, err := c.GetAccountStatus(ctx)
	if err != nil {
		t.Errorf("GetAccountStatus() error = %v", err)
	}

	if status.IsExpired {
		t.Error("GetAccountStatus() reported account as expired")
	}
	if status.DaysLeft < 29 || status.DaysLeft > 31 {
		t.Errorf("GetAccountStatus() DaysLeft = %d, want ~30", status.DaysLeft)
	}
}

func TestRegisterDevice(t *testing.T) {
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "1")

	mock := &mockMullvadServer{
		t:      t,
		expiry: time.Now().Add(30 * 24 * time.Hour),
	}
	server := httptest.NewServer(mock)
	defer server.Close()

	c, err := NewClient("1234567890123456", t.Logf, nil, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c.apiBase = server.URL

	ctx := context.Background()

	// Generate a test key
	nodeKey := key.NewNode()
	pubKey := nodeKey.Public()

	info, err := c.RegisterDevice(ctx, pubKey)
	if err != nil {
		t.Fatalf("RegisterDevice() error = %v", err)
	}

	if info.ID != "test-device-id" {
		t.Errorf("RegisterDevice() ID = %s, want test-device-id", info.ID)
	}
	if !info.IPv4Address.IsValid() {
		t.Error("RegisterDevice() returned invalid IPv4 address")
	}
}

func TestGetServers(t *testing.T) {
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "1")

	// Generate a valid base64-encoded public key
	nodeKey := key.NewNode()
	pubKeyBytes := nodeKey.Public().Raw32()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes[:])

	mock := &mockMullvadServer{
		t:      t,
		expiry: time.Now().Add(30 * 24 * time.Hour),
		servers: []relayResponse{
			{
				Hostname:   "us-nyc-wg-001",
				Location:   "us-nyc",
				IPv4AddrIn: "193.27.12.1",
				IPv6AddrIn: "2a03:1b20:3:f011::a01f",
				PublicKey:  pubKeyB64,
				Active:     true,
				Owned:      true,
			},
			{
				Hostname:   "de-fra-wg-001",
				Location:   "de-fra",
				IPv4AddrIn: "185.213.154.1",
				IPv6AddrIn: "2a03:1b20:6:f011::a01f",
				PublicKey:  pubKeyB64,
				Active:     true,
				Owned:      true,
			},
		},
	}
	server := httptest.NewServer(mock)
	defer server.Close()

	c, err := NewClient("1234567890123456", t.Logf, nil, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c.apiBase = server.URL

	ctx := context.Background()
	servers, err := c.GetServers(ctx)
	if err != nil {
		t.Fatalf("GetServers() error = %v", err)
	}

	if len(servers) != 2 {
		t.Errorf("GetServers() returned %d servers, want 2", len(servers))
	}

	// Verify first server details
	if servers[0].Hostname != "us-nyc-wg-001" {
		t.Errorf("GetServers()[0].Hostname = %s, want us-nyc-wg-001", servers[0].Hostname)
	}
	if servers[0].CountryCode != "us" {
		t.Errorf("GetServers()[0].CountryCode = %s, want us", servers[0].CountryCode)
	}
	if !servers[0].Active {
		t.Error("GetServers()[0].Active = false, want true")
	}
}

func TestServerCache(t *testing.T) {
	t.Setenv("TS_ENABLE_CUSTOM_MULLVAD", "1")

	nodeKey := key.NewNode()
	pubKeyBytes := nodeKey.Public().Raw32()
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes[:])

	var callCount atomic.Int32
	mock := &mockMullvadServer{
		t:      t,
		expiry: time.Now().Add(30 * 24 * time.Hour),
		servers: []relayResponse{
			{
				Hostname:   "us-nyc-wg-001",
				Location:   "us-nyc",
				IPv4AddrIn: "193.27.12.1",
				PublicKey:  pubKeyB64,
				Active:     true,
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/public/relays/wireguard/v2/", func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		mock.ServeHTTP(w, r)
	})
	mux.HandleFunc("/", mock.ServeHTTP)

	server := httptest.NewServer(mux)
	defer server.Close()

	c, err := NewClient("1234567890123456", t.Logf, nil, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	c.apiBase = server.URL

	ctx := context.Background()

	// First call
	_, err = c.GetServers(ctx)
	if err != nil {
		t.Fatalf("GetServers() error = %v", err)
	}

	// Second call should use cache
	_, err = c.GetServers(ctx)
	if err != nil {
		t.Fatalf("GetServers() error = %v", err)
	}

	if callCount.Load() != 1 {
		t.Errorf("GetServers() made %d API calls, want 1 (cache should be used)", callCount.Load())
	}
}
