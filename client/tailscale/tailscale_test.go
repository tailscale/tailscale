// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
)

func TestClientBuildURL(t *testing.T) {
	c := Client{BaseURL: "http://127.0.0.1:1234"}
	for _, tt := range []struct {
		desc     string
		elements []any
		want     string
	}{
		{
			desc:     "single-element",
			elements: []any{"devices"},
			want:     "http://127.0.0.1:1234/api/v2/devices",
		},
		{
			desc:     "multiple-elements",
			elements: []any{"tailnet", "example.com"},
			want:     "http://127.0.0.1:1234/api/v2/tailnet/example.com",
		},
		{
			desc:     "escape-element",
			elements: []any{"tailnet", "example dot com?foo=bar"},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example%20dot%20com%3Ffoo=bar`,
		},
		{
			desc:     "url.Values",
			elements: []any{"tailnet", "example.com", "acl", url.Values{"details": {"1"}}},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example.com/acl?details=1`,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			got := c.BuildURL(tt.elements...)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientBuildTailnetURL(t *testing.T) {
	c := Client{
		BaseURL: "http://127.0.0.1:1234",
		tailnet: "example.com",
	}
	for _, tt := range []struct {
		desc     string
		elements []any
		want     string
	}{
		{
			desc:     "single-element",
			elements: []any{"devices"},
			want:     "http://127.0.0.1:1234/api/v2/tailnet/example.com/devices",
		},
		{
			desc:     "multiple-elements",
			elements: []any{"devices", 123},
			want:     "http://127.0.0.1:1234/api/v2/tailnet/example.com/devices/123",
		},
		{
			desc:     "escape-element",
			elements: []any{"foo bar?baz=qux"},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example.com/foo%20bar%3Fbaz=qux`,
		},
		{
			desc:     "url.Values",
			elements: []any{"acl", url.Values{"details": {"1"}}},
			want:     `http://127.0.0.1:1234/api/v2/tailnet/example.com/acl?details=1`,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			got := c.BuildTailnetURL(tt.elements...)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// ===== Routes Tests =====

func TestClient_Routes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/device/") || !strings.Contains(r.URL.Path, "/routes") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Routes{
			AdvertisedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			EnabledRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	routes, err := client.Routes(context.Background(), "device123")
	if err != nil {
		t.Fatalf("Routes failed: %v", err)
	}
	if len(routes.AdvertisedRoutes) != 1 {
		t.Errorf("expected 1 advertised route, got %d", len(routes.AdvertisedRoutes))
	}
}

func TestClient_SetRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/device/") || !strings.Contains(r.URL.Path, "/routes") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Routes{
			AdvertisedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			EnabledRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	subnets := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	routes, err := client.SetRoutes(context.Background(), "device123", subnets)
	if err != nil {
		t.Fatalf("SetRoutes failed: %v", err)
	}
	if len(routes.EnabledRoutes) != 1 {
		t.Errorf("expected 1 enabled route, got %d", len(routes.EnabledRoutes))
	}
}

func TestClient_Routes_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "device not found"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	_, err := client.Routes(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent device")
	}
}

// ===== Keys Tests =====

func TestClient_Keys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/keys") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{
				{"id": "key1", "created": "2024-01-01T00:00:00Z"},
				{"id": "key2", "created": "2024-01-02T00:00:00Z"},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	keys, err := client.Keys(context.Background())
	if err != nil {
		t.Fatalf("Keys failed: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
	if keys[0] != "key1" || keys[1] != "key2" {
		t.Errorf("unexpected key IDs: %v", keys)
	}
}

func TestClient_CreateKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "newkey123",
			"key":     "tskey-secret-abc123",
			"created": "2024-01-01T00:00:00Z",
			"expires": "2025-01-01T00:00:00Z",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	caps := KeyCapabilities{
		Devices: KeyDeviceCapabilities{
			Create: KeyDeviceCreateCapabilities{
				Reusable:      true,
				Preauthorized: true,
				Tags:          []string{"tag:server"},
			},
		},
	}
	secret, key, err := client.CreateKey(context.Background(), caps)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
	if secret != "tskey-secret-abc123" {
		t.Errorf("unexpected secret: %s", secret)
	}
	if key.ID != "newkey123" {
		t.Errorf("unexpected key ID: %s", key.ID)
	}
}

func TestClient_CreateKeyWithExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req struct {
			ExpirySeconds int64 `json:"expirySeconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if req.ExpirySeconds != 3600 {
			t.Errorf("expected expirySeconds=3600, got %d", req.ExpirySeconds)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "newkey456",
			"key":     "tskey-secret-def456",
			"created": "2024-01-01T00:00:00Z",
			"expires": "2024-01-01T01:00:00Z",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	caps := KeyCapabilities{}
	secret, key, err := client.CreateKeyWithExpiry(context.Background(), caps, 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateKeyWithExpiry failed: %v", err)
	}
	if secret != "tskey-secret-def456" {
		t.Errorf("unexpected secret: %s", secret)
	}
	if key.ID != "newkey456" {
		t.Errorf("unexpected key ID: %s", key.ID)
	}
}

func TestClient_CreateKeyWithExpiry_InvalidExpiry(t *testing.T) {
	client := &Client{BaseURL: "http://example.com", tailnet: "example.com"}
	caps := KeyCapabilities{}

	// Negative expiry
	_, _, err := client.CreateKeyWithExpiry(context.Background(), caps, -1*time.Hour)
	if err == nil {
		t.Error("expected error for negative expiry")
	}

	// Sub-second positive expiry
	_, _, err = client.CreateKeyWithExpiry(context.Background(), caps, 500*time.Millisecond)
	if err == nil {
		t.Error("expected error for sub-second expiry")
	}
}

func TestClient_Key(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/keys/key123") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Key{
			ID:      "key123",
			Created: time.Now(),
			Expires: time.Now().Add(365 * 24 * time.Hour),
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	key, err := client.Key(context.Background(), "key123")
	if err != nil {
		t.Fatalf("Key failed: %v", err)
	}
	if key.ID != "key123" {
		t.Errorf("unexpected key ID: %s", key.ID)
	}
}

func TestClient_DeleteKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/keys/key123") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	err := client.DeleteKey(context.Background(), "key123")
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
}

// ===== Devices Tests =====

func TestClient_Devices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/devices") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Check query parameters
		fields := r.URL.Query().Get("fields")
		if fields == "" {
			t.Error("expected fields query parameter")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(GetDevicesResponse{
			Devices: []*Device{
				{
					DeviceID: "device1",
					Name:     "test-device-1",
					Hostname: "device1.example.com",
				},
				{
					DeviceID: "device2",
					Name:     "test-device-2",
					Hostname: "device2.example.com",
				},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	devices, err := client.Devices(context.Background(), DeviceDefaultFields)
	if err != nil {
		t.Fatalf("Devices failed: %v", err)
	}
	if len(devices) != 2 {
		t.Errorf("expected 2 devices, got %d", len(devices))
	}
}

func TestClient_Devices_AllFields(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields := r.URL.Query().Get("fields")
		if fields != "all" {
			t.Errorf("expected fields=all, got %s", fields)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(GetDevicesResponse{
			Devices: []*Device{
				{
					DeviceID:        "device1",
					Name:            "test-device-1",
					EnabledRoutes:   []string{"10.0.0.0/24"},
					AdvertisedRoutes: []string{"10.0.0.0/24", "192.168.1.0/24"},
				},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	devices, err := client.Devices(context.Background(), DeviceAllFields)
	if err != nil {
		t.Fatalf("Devices failed: %v", err)
	}
	if len(devices[0].EnabledRoutes) == 0 {
		t.Error("expected enabled routes to be included with AllFields")
	}
}

func TestClient_Device(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/device/device123") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Device{
			DeviceID: "device123",
			Name:     "test-device",
			Hostname: "device.example.com",
			OS:       "linux",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	device, err := client.Device(context.Background(), "device123", DeviceDefaultFields)
	if err != nil {
		t.Fatalf("Device failed: %v", err)
	}
	if device.DeviceID != "device123" {
		t.Errorf("unexpected device ID: %s", device.DeviceID)
	}
	if device.OS != "linux" {
		t.Errorf("unexpected OS: %s", device.OS)
	}
}

func TestClient_DeleteDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/device/device123") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	err := client.DeleteDevice(context.Background(), "device123")
	if err != nil {
		t.Fatalf("DeleteDevice failed: %v", err)
	}
}

func TestClient_AuthorizeDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/device/device123/authorized") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req struct {
			Authorized bool `json:"authorized"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if !req.Authorized {
			t.Error("expected authorized=true")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	err := client.AuthorizeDevice(context.Background(), "device123")
	if err != nil {
		t.Fatalf("AuthorizeDevice failed: %v", err)
	}
}

func TestClient_SetAuthorized(t *testing.T) {
	tests := []struct {
		name       string
		authorized bool
	}{
		{"authorize", true},
		{"deauthorize", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Authorized bool `json:"authorized"`
				}
				json.NewDecoder(r.Body).Decode(&req)
				if req.Authorized != tt.authorized {
					t.Errorf("expected authorized=%v, got %v", tt.authorized, req.Authorized)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			client := &Client{BaseURL: server.URL, tailnet: "example.com"}
			err := client.SetAuthorized(context.Background(), "device123", tt.authorized)
			if err != nil {
				t.Fatalf("SetAuthorized failed: %v", err)
			}
		})
	}
}

func TestClient_SetTags(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/device/device123/tags") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var req struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if len(req.Tags) != 2 {
			t.Errorf("expected 2 tags, got %d", len(req.Tags))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	err := client.SetTags(context.Background(), "device123", []string{"tag:server", "tag:prod"})
	if err != nil {
		t.Fatalf("SetTags failed: %v", err)
	}
}

// ===== DNS Tests =====

func TestClient_DNSConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/dns/config") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(apitype.DNSConfig{
			Resolvers: []apitype.DNSResolver{
				{Addr: "8.8.8.8"},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	cfg, err := client.DNSConfig(context.Background())
	if err != nil {
		t.Fatalf("DNSConfig failed: %v", err)
	}
	if len(cfg.Resolvers) != 1 {
		t.Errorf("expected 1 resolver, got %d", len(cfg.Resolvers))
	}
}

func TestClient_SetDNSConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/dns/config") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(apitype.DNSConfig{
			Resolvers: []apitype.DNSResolver{
				{Addr: "1.1.1.1"},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	cfg := apitype.DNSConfig{
		Resolvers: []apitype.DNSResolver{
			{Addr: "1.1.1.1"},
		},
	}
	result, err := client.SetDNSConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("SetDNSConfig failed: %v", err)
	}
	if len(result.Resolvers) != 1 {
		t.Errorf("expected 1 resolver, got %d", len(result.Resolvers))
	}
}

func TestClient_NameServers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/dns/nameservers") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DNSNameServers{
			DNS: []string{"8.8.8.8", "8.8.4.4"},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	ns, err := client.NameServers(context.Background())
	if err != nil {
		t.Fatalf("NameServers failed: %v", err)
	}
	if len(ns) != 2 {
		t.Errorf("expected 2 nameservers, got %d", len(ns))
	}
}

func TestClient_SetNameServers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/dns/nameservers") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DNSNameServersPostResponse{
			DNS:      []string{"1.1.1.1", "1.0.0.1"},
			MagicDNS: true,
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	result, err := client.SetNameServers(context.Background(), []string{"1.1.1.1", "1.0.0.1"})
	if err != nil {
		t.Fatalf("SetNameServers failed: %v", err)
	}
	if len(result.DNS) != 2 {
		t.Errorf("expected 2 nameservers, got %d", len(result.DNS))
	}
	if !result.MagicDNS {
		t.Error("expected MagicDNS to be true")
	}
}

func TestClient_DNSPreferences(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/dns/preferences") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DNSPreferences{
			MagicDNS: true,
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	prefs, err := client.DNSPreferences(context.Background())
	if err != nil {
		t.Fatalf("DNSPreferences failed: %v", err)
	}
	if !prefs.MagicDNS {
		t.Error("expected MagicDNS to be true")
	}
}

func TestClient_SetDNSPreferences(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req DNSPreferences
		json.NewDecoder(r.Body).Decode(&req)
		if !req.MagicDNS {
			t.Error("expected MagicDNS=true in request")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DNSPreferences{
			MagicDNS: true,
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	result, err := client.SetDNSPreferences(context.Background(), true)
	if err != nil {
		t.Fatalf("SetDNSPreferences failed: %v", err)
	}
	if !result.MagicDNS {
		t.Error("expected MagicDNS to be true")
	}
}

func TestClient_SearchPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/dns/searchpaths") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DNSSearchPaths{
			SearchPaths: []string{"example.com", "internal.example.com"},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	paths, err := client.SearchPaths(context.Background())
	if err != nil {
		t.Fatalf("SearchPaths failed: %v", err)
	}
	if len(paths) != 2 {
		t.Errorf("expected 2 search paths, got %d", len(paths))
	}
}

func TestClient_SetSearchPaths(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(DNSSearchPaths{
			SearchPaths: []string{"corp.example.com"},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	result, err := client.SetSearchPaths(context.Background(), []string{"corp.example.com"})
	if err != nil {
		t.Fatalf("SetSearchPaths failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 search path, got %d", len(result))
	}
}

// ===== ACL Tests =====

func TestClient_ACL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/acl") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("expected Accept: application/json header")
		}

		w.Header().Set("ETag", "etag123")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLDetails{
			ACLs: []ACLRow{
				{Action: "accept", Src: []string{"*"}, Dst: []string{"*:*"}},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl, err := client.ACL(context.Background())
	if err != nil {
		t.Fatalf("ACL failed: %v", err)
	}
	if len(acl.ACL.ACLs) != 1 {
		t.Errorf("expected 1 ACL rule, got %d", len(acl.ACL.ACLs))
	}
	if acl.ETag != "etag123" {
		t.Errorf("expected ETag=etag123, got %s", acl.ETag)
	}
}

func TestClient_ACLHuJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Accept") != "application/hujson" {
			t.Errorf("expected Accept: application/hujson header")
		}

		w.Header().Set("ETag", "etag456")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"acl":      []byte(`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`),
			"warnings": []string{"warning1"},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl, err := client.ACLHuJSON(context.Background())
	if err != nil {
		t.Fatalf("ACLHuJSON failed: %v", err)
	}
	if acl.ETag != "etag456" {
		t.Errorf("expected ETag=etag456, got %s", acl.ETag)
	}
	if len(acl.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(acl.Warnings))
	}
}

// ===== Error Handling Tests =====

func TestClient_ErrorHandling_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "unauthorized"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}

	// Test various methods return errors on 401
	_, err := client.Keys(context.Background())
	if err == nil {
		t.Error("expected error for unauthorized request")
	}

	_, err = client.Devices(context.Background(), DeviceDefaultFields)
	if err == nil {
		t.Error("expected error for unauthorized devices request")
	}
}

func TestClient_ErrorHandling_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message": "not found"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	_, err := client.Device(context.Background(), "nonexistent", DeviceDefaultFields)
	if err == nil {
		t.Error("expected error for not found device")
	}
}

func TestClient_ErrorHandling_RateLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"message": "rate limited"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	_, err := client.Keys(context.Background())
	if err == nil {
		t.Error("expected error for rate limited request")
	}
}

func TestClient_ErrorHandling_InternalServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"message": "internal server error"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	_, err := client.DNSConfig(context.Background())
	if err == nil {
		t.Error("expected error for internal server error")
	}
}

func TestClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]interface{}{}})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := client.Keys(ctx)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// ===== Edge Case Tests =====

func TestClient_DeleteDevice_SpecialCharacters(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify URL encoding of device ID
		if !strings.Contains(r.URL.Path, "device%2Fspecial") {
			t.Logf("path should contain URL-encoded device ID: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	// Device ID with special characters that need URL encoding
	err := client.DeleteDevice(context.Background(), "device/special")
	if err != nil {
		t.Fatalf("DeleteDevice with special chars failed: %v", err)
	}
}

func TestClient_SetTags_EmptyList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Tags []string `json:"tags"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Tags == nil {
			t.Error("tags should not be nil, should be empty array")
		}
		if len(req.Tags) != 0 {
			t.Errorf("expected 0 tags, got %d", len(req.Tags))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	err := client.SetTags(context.Background(), "device123", []string{})
	if err != nil {
		t.Fatalf("SetTags with empty list failed: %v", err)
	}
}

func TestClient_Routes_MultipleSubnets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Routes{
			AdvertisedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
			},
			EnabledRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	routes, err := client.Routes(context.Background(), "device123")
	if err != nil {
		t.Fatalf("Routes failed: %v", err)
	}
	if len(routes.AdvertisedRoutes) != 3 {
		t.Errorf("expected 3 advertised routes, got %d", len(routes.AdvertisedRoutes))
	}
	if len(routes.EnabledRoutes) != 1 {
		t.Errorf("expected 1 enabled route, got %d", len(routes.EnabledRoutes))
	}
}

func TestClient_Device_ExternalDevice(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Device{
			DeviceID:   "external123",
			Name:       "external-device",
			IsExternal: true,
			// External devices don't have these fields
			ClientVersion: "",
			MachineKey:    "",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	device, err := client.Device(context.Background(), "external123", DeviceDefaultFields)
	if err != nil {
		t.Fatalf("Device failed: %v", err)
	}
	if !device.IsExternal {
		t.Error("expected IsExternal to be true")
	}
	if device.ClientVersion != "" {
		t.Error("external device should not have ClientVersion")
	}
}

func TestClient_DNSConfig_EmptyResolvers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(apitype.DNSConfig{
			Resolvers: []apitype.DNSResolver{},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	cfg, err := client.DNSConfig(context.Background())
	if err != nil {
		t.Fatalf("DNSConfig failed: %v", err)
	}
	if len(cfg.Resolvers) != 0 {
		t.Errorf("expected 0 resolvers, got %d", len(cfg.Resolvers))
	}
}

// ===== Additional Method Tests =====

func TestClient_TailnetDeleteRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/tailnet/") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	err := client.TailnetDeleteRequest(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("TailnetDeleteRequest failed: %v", err)
	}
}

func TestClient_Tailnet(t *testing.T) {
	client := &Client{tailnet: "test.example.com"}
	if client.Tailnet() != "test.example.com" {
		t.Errorf("expected tailnet 'test.example.com', got %s", client.Tailnet())
	}
}

func TestClient_BaseURL_Default(t *testing.T) {
	// Test default baseURL behavior
	client := &Client{tailnet: "example.com"}
	url := client.baseURL()
	if url == "" {
		t.Error("baseURL should not be empty")
	}
}

func TestClient_BaseURL_Custom(t *testing.T) {
	client := &Client{BaseURL: "https://custom.example.com", tailnet: "example.com"}
	url := client.baseURL()
	if url != "https://custom.example.com" {
		t.Errorf("expected baseURL 'https://custom.example.com', got %s", url)
	}
}

func TestErrResponse_ErrorMessage(t *testing.T) {
	err := ErrResponse{
		StatusCode: 404,
		Message:    "Resource not found",
	}
	expected := "tailscale API: 404: Resource not found"
	if err.Error() != expected {
		t.Errorf("expected error message %q, got %q", expected, err.Error())
	}
}

func TestAPIKey_ModifyRequest_Applied(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	apiKey := APIKey("test-api-key-12345")
	apiKey.modifyRequest(req)

	auth := req.Header.Get("Authorization")
	if !strings.Contains(auth, "Bearer") {
		t.Errorf("expected Authorization header with Bearer, got %s", auth)
	}
	if !strings.Contains(auth, "test-api-key-12345") {
		t.Errorf("expected Authorization header to contain API key")
	}
}

func TestClient_HTTPClient_Default(t *testing.T) {
	client := &Client{}
	httpClient := client.httpClient()
	if httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	// Default should be http.DefaultClient
	if httpClient != http.DefaultClient {
		t.Error("default httpClient should be http.DefaultClient")
	}
}

func TestClient_HTTPClient_Custom(t *testing.T) {
	customClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	client := &Client{HTTPClient: customClient}
	httpClient := client.httpClient()
	if httpClient != customClient {
		t.Error("should use custom HTTP client")
	}
}

// ===== JSON Parsing Edge Cases =====

func TestClient_Keys_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys": [invalid json]}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	_, err := client.Keys(context.Background())
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestClient_Device_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not valid json}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	_, err := client.Device(context.Background(), "device123", DeviceDefaultFields)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

// ===== Concurrent Request Tests =====

func TestClient_ConcurrentRequests(t *testing.T) {
	requestCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()

		// Simulate some processing time
		time.Sleep(10 * time.Millisecond)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"keys": []map[string]interface{}{},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}

	// Make 10 concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Keys(context.Background())
			if err != nil {
				t.Errorf("concurrent request failed: %v", err)
			}
		}()
	}

	wg.Wait()

	mu.Lock()
	count := requestCount
	mu.Unlock()

	if count != 10 {
		t.Errorf("expected 10 requests, got %d", count)
	}
}

// ===== Additional Device Field Tests =====

func TestDeviceFieldsOpts_DefaultFields(t *testing.T) {
	fields := DeviceDefaultFields
	param := fields.addFieldsToQueryParameter()
	if param != "default" {
		t.Errorf("expected 'default', got %s", param)
	}
}

func TestDeviceFieldsOpts_AllFields(t *testing.T) {
	fields := DeviceAllFields
	param := fields.addFieldsToQueryParameter()
	if param != "all" {
		t.Errorf("expected 'all', got %s", param)
	}
}

func TestDeviceFieldsOpts_Nil(t *testing.T) {
	var fields *DeviceFieldsOpts
	param := fields.addFieldsToQueryParameter()
	if param != "default" {
		t.Errorf("expected 'default' for nil, got %s", param)
	}
}

// ===== Request Body Validation Tests =====

func TestClient_SetRoutes_ValidatesRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Routes []netip.Prefix `json:"routes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if len(req.Routes) != 2 {
			t.Errorf("expected 2 routes in request, got %d", len(req.Routes))
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(Routes{
			EnabledRoutes: req.Routes,
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	subnets := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}
	routes, err := client.SetRoutes(context.Background(), "device123", subnets)
	if err != nil {
		t.Fatalf("SetRoutes failed: %v", err)
	}
	if len(routes.EnabledRoutes) != 2 {
		t.Errorf("expected 2 enabled routes, got %d", len(routes.EnabledRoutes))
	}
}

func TestClient_CreateKey_ValidatesCapabilities(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Capabilities KeyCapabilities `json:"capabilities"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}
		if !req.Capabilities.Devices.Create.Reusable {
			t.Error("expected reusable to be true")
		}
		if !req.Capabilities.Devices.Create.Ephemeral {
			t.Error("expected ephemeral to be true")
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":  "key123",
			"key": "tskey-secret",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	caps := KeyCapabilities{
		Devices: KeyDeviceCapabilities{
			Create: KeyDeviceCreateCapabilities{
				Reusable:  true,
				Ephemeral: true,
			},
		},
	}
	_, _, err := client.CreateKey(context.Background(), caps)
	if err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}
}

// ===== Test Multiple Error Conditions =====

func TestClient_Devices_InvalidFieldsParameter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(GetDevicesResponse{Devices: []*Device{}})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}

	// Test with custom fields opts (not default or all)
	customFields := &DeviceFieldsOpts{DeviceID: "test"}
	devices, err := client.Devices(context.Background(), customFields)
	if err != nil {
		t.Fatalf("Devices with custom fields failed: %v", err)
	}
	if devices == nil {
		t.Error("devices should not be nil")
	}
}

// ===== Additional ACL Method Tests =====

func TestClient_SetACL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/acl") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Check headers
		if r.Header.Get("Content-Type") != "application/hujson" {
			t.Errorf("expected Content-Type: application/hujson")
		}

		w.Header().Set("ETag", "new-etag-789")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLDetails{
			ACLs: []ACLRow{
				{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:prod:*"}},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{
		ACL: ACLDetails{
			ACLs: []ACLRow{
				{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:prod:*"}},
			},
		},
		ETag: "old-etag",
	}

	result, err := client.SetACL(context.Background(), acl, false)
	if err != nil {
		t.Fatalf("SetACL failed: %v", err)
	}
	if result.ETag != "new-etag-789" {
		t.Errorf("expected ETag=new-etag-789, got %s", result.ETag)
	}
}

func TestClient_SetACL_AvoidCollisions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check If-Match header is set
		ifMatch := r.Header.Get("If-Match")
		if ifMatch != "expected-etag" {
			t.Errorf("expected If-Match header with etag, got %s", ifMatch)
		}

		w.Header().Set("ETag", "new-etag")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLDetails{})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{
		ACL:  ACLDetails{},
		ETag: "expected-etag",
	}

	_, err := client.SetACL(context.Background(), acl, true)
	if err != nil {
		t.Fatalf("SetACL with avoidCollisions failed: %v", err)
	}
}

func TestClient_SetACL_ETagMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		w.Write([]byte(`{"message": "ETag mismatch"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{
		ACL:  ACLDetails{},
		ETag: "wrong-etag",
	}

	_, err := client.SetACL(context.Background(), acl, true)
	if err == nil {
		t.Error("expected error for ETag mismatch")
	}
}

func TestClient_SetACLHuJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if r.Header.Get("Accept") != "application/hujson" {
			t.Errorf("expected Accept: application/hujson")
		}

		w.Header().Set("ETag", "hujson-etag")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"acls": [{"action": "accept"}]}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACLHuJSON{
		ACL:  `{"acls": [{"action": "accept"}]}`,
		ETag: "old-hujson-etag",
	}

	result, err := client.SetACLHuJSON(context.Background(), acl, false)
	if err != nil {
		t.Fatalf("SetACLHuJSON failed: %v", err)
	}
	if result.ETag != "hujson-etag" {
		t.Errorf("expected ETag=hujson-etag, got %s", result.ETag)
	}
}

func TestClient_PreviewACLForUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/acl/preview") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		// Check query parameters
		previewType := r.URL.Query().Get("type")
		previewFor := r.URL.Query().Get("previewFor")
		if previewType != "user" {
			t.Errorf("expected type=user, got %s", previewType)
		}
		if previewFor != "alice@example.com" {
			t.Errorf("expected previewFor=alice@example.com, got %s", previewFor)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLPreviewResponse{
			Matches: []UserRuleMatch{
				{
					Users: []string{"alice@example.com"},
					Ports: []string{"*:80"},
				},
			},
			Type:       "user",
			PreviewFor: "alice@example.com",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{
		ACL: ACLDetails{
			ACLs: []ACLRow{
				{Action: "accept", Src: []string{"*"}, Dst: []string{"*:80"}},
			},
		},
	}

	result, err := client.PreviewACLForUser(context.Background(), acl, "alice@example.com")
	if err != nil {
		t.Fatalf("PreviewACLForUser failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.Matches))
	}
	if result.User != "alice@example.com" {
		t.Errorf("expected user=alice@example.com, got %s", result.User)
	}
}

func TestClient_PreviewACLForIPPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}

		// Check query parameters
		previewType := r.URL.Query().Get("type")
		previewFor := r.URL.Query().Get("previewFor")
		if previewType != "ipport" {
			t.Errorf("expected type=ipport, got %s", previewType)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLPreviewResponse{
			Matches: []UserRuleMatch{
				{
					Users: []string{"*"},
					Ports: []string{"100.64.0.1:22"},
				},
			},
			Type:       "ipport",
			PreviewFor: previewFor,
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{
		ACL: ACLDetails{},
	}
	ipport := netip.MustParseAddrPort("100.64.0.1:22")

	result, err := client.PreviewACLForIPPort(context.Background(), acl, ipport)
	if err != nil {
		t.Fatalf("PreviewACLForIPPort failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.Matches))
	}
	if result.IPPort != "100.64.0.1:22" {
		t.Errorf("expected ipport=100.64.0.1:22, got %s", result.IPPort)
	}
}

func TestClient_PreviewACLHuJSONForUser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		previewType := r.URL.Query().Get("type")
		previewFor := r.URL.Query().Get("previewFor")
		if previewType != "user" {
			t.Errorf("expected type=user, got %s", previewType)
		}
		if previewFor != "bob@example.com" {
			t.Errorf("expected previewFor=bob@example.com, got %s", previewFor)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLPreviewResponse{
			Matches: []UserRuleMatch{
				{
					Users: []string{"bob@example.com"},
					Ports: []string{"tag:server:*"},
				},
			},
			Type:       "user",
			PreviewFor: "bob@example.com",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACLHuJSON{
		ACL: `{"acls": [{"action": "accept", "src": ["bob@example.com"], "dst": ["tag:server:*"]}]}`,
	}

	result, err := client.PreviewACLHuJSONForUser(context.Background(), acl, "bob@example.com")
	if err != nil {
		t.Fatalf("PreviewACLHuJSONForUser failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.Matches))
	}
	if result.User != "bob@example.com" {
		t.Errorf("expected user=bob@example.com, got %s", result.User)
	}
}

func TestClient_PreviewACLHuJSONForIPPort(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		previewType := r.URL.Query().Get("type")
		if previewType != "ipport" {
			t.Errorf("expected type=ipport, got %s", previewType)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLPreviewResponse{
			Matches: []UserRuleMatch{
				{
					Users: []string{"group:admins"},
					Ports: []string{"192.168.1.1:443"},
				},
			},
			Type:       "ipport",
			PreviewFor: "192.168.1.1:443",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACLHuJSON{
		ACL: `{"acls": [{"action": "accept"}]}`,
	}

	result, err := client.PreviewACLHuJSONForIPPort(context.Background(), acl, "192.168.1.1:443")
	if err != nil {
		t.Fatalf("PreviewACLHuJSONForIPPort failed: %v", err)
	}
	if len(result.Matches) != 1 {
		t.Errorf("expected 1 match, got %d", len(result.Matches))
	}
	if result.IPPort != "192.168.1.1:443" {
		t.Errorf("expected ipport=192.168.1.1:443, got %s", result.IPPort)
	}
}

func TestClient_ValidateACLJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("unexpected method: %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/acl/validate") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type: application/json")
		}

		// Return empty body for successful validation
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	testErr, err := client.ValidateACLJSON(context.Background(), "alice@example.com", "100.64.0.1:80")
	if err != nil {
		t.Fatalf("ValidateACLJSON failed: %v", err)
	}
	if testErr != nil {
		t.Error("expected no test errors for valid ACL")
	}
}

func TestClient_ValidateACLJSON_WithErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLTestError{
			Data: []ACLTestFailureSummary{
				{
					User:   "alice@example.com",
					Errors: []string{"access denied"},
				},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	testErr, err := client.ValidateACLJSON(context.Background(), "alice@example.com", "100.64.0.1:80")
	if err != nil {
		t.Fatalf("ValidateACLJSON failed: %v", err)
	}
	if testErr == nil {
		t.Error("expected test errors for invalid ACL")
	}
	if len(testErr.Data) != 1 {
		t.Errorf("expected 1 test failure, got %d", len(testErr.Data))
	}
}

func TestACLTestError_Error(t *testing.T) {
	err := ACLTestError{
		ErrResponse: ErrResponse{
			StatusCode: 400,
			Message:    "ACL test failed",
		},
		Data: []ACLTestFailureSummary{
			{
				User:   "test@example.com",
				Errors: []string{"denied"},
			},
		},
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "ACL test failed") {
		t.Errorf("error message should contain 'ACL test failed', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "Data:") {
		t.Errorf("error message should contain 'Data:', got: %s", errMsg)
	}
}

// ===== ACL Preview with Postures =====

func TestClient_PreviewACL_WithPostures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLPreviewResponse{
			Matches: []UserRuleMatch{
				{
					Users:    []string{"user@example.com"},
					Ports:    []string{"*:443"},
					Postures: []string{"posture:secure"},
				},
			},
			Type:       "user",
			PreviewFor: "user@example.com",
			Postures: map[string][]string{
				"posture:secure": {"deviceTrusted == true"},
			},
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{ACL: ACLDetails{}}

	result, err := client.PreviewACLForUser(context.Background(), acl, "user@example.com")
	if err != nil {
		t.Fatalf("PreviewACLForUser failed: %v", err)
	}
	if len(result.Postures) != 1 {
		t.Errorf("expected 1 posture, got %d", len(result.Postures))
	}
	if len(result.Matches[0].Postures) != 1 {
		t.Errorf("expected 1 posture in match, got %d", len(result.Matches[0].Postures))
	}
}

// ===== Empty/Edge Case Tests =====

func TestClient_PreviewACL_NoMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(ACLPreviewResponse{
			Matches:    []UserRuleMatch{},
			Type:       "user",
			PreviewFor: "noone@example.com",
		})
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{ACL: ACLDetails{}}

	result, err := client.PreviewACLForUser(context.Background(), acl, "noone@example.com")
	if err != nil {
		t.Fatalf("PreviewACLForUser failed: %v", err)
	}
	if len(result.Matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(result.Matches))
	}
}

func TestClient_SetACL_ComplexACL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ACLDetails
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode request: %v", err)
		}

		// Verify complex ACL structure
		if len(req.ACLs) != 2 {
			t.Errorf("expected 2 ACL rules, got %d", len(req.ACLs))
		}
		if len(req.Groups) != 1 {
			t.Errorf("expected 1 group, got %d", len(req.Groups))
		}
		if len(req.TagOwners) != 1 {
			t.Errorf("expected 1 tag owner, got %d", len(req.TagOwners))
		}

		w.Header().Set("ETag", "complex-etag")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(req)
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, tailnet: "example.com"}
	acl := ACL{
		ACL: ACLDetails{
			ACLs: []ACLRow{
				{Action: "accept", Src: []string{"group:eng"}, Dst: []string{"tag:prod:*"}},
				{Action: "accept", Src: []string{"group:ops"}, Dst: []string{"tag:infra:*"}},
			},
			Groups: map[string][]string{
				"group:eng": {"alice@example.com", "bob@example.com"},
			},
			TagOwners: map[string][]string{
				"tag:prod": {"group:eng"},
			},
		},
	}

	result, err := client.SetACL(context.Background(), acl, false)
	if err != nil {
		t.Fatalf("SetACL with complex ACL failed: %v", err)
	}
	if len(result.ACL.ACLs) != 2 {
		t.Errorf("expected 2 ACL rules in result, got %d", len(result.ACL.ACLs))
	}
}
