// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mullvad provides a client for the Mullvad VPN API,
// enabling "Bring Your Own Mullvad Account" functionality.
package mullvad

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/envknob"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netx"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// CustomMullvadEnabled reports whether custom Mullvad account support is enabled.
func CustomMullvadEnabled() bool {
	return envknob.Bool("TS_ENABLE_CUSTOM_MULLVAD")
}

const (
	// defaultAPIBase is the base URL for the Mullvad API.
	defaultAPIBase = "https://api.mullvad.net"

	// defaultWireGuardPort is the default WireGuard port for Mullvad servers.
	defaultWireGuardPort = 51820

	// serverCacheExpiry is how long to cache the server list.
	serverCacheExpiry = 6 * time.Hour

	// tokenRefreshMargin is how long before expiry to refresh the token.
	tokenRefreshMargin = 5 * time.Minute

	// maxAPIResponseSize is the maximum size of API response bodies we'll read.
	maxAPIResponseSize = 1 << 20 // 1MB
)

var (
	// ErrAccountExpired is returned when the Mullvad account has expired.
	ErrAccountExpired = errors.New("mullvad account has expired")

	// ErrInvalidAccount is returned when the account number is invalid.
	ErrInvalidAccount = errors.New("invalid mullvad account number")

	// ErrDeviceLimitReached is returned when the device limit is reached.
	ErrDeviceLimitReached = errors.New("mullvad device limit reached")

	// ErrNotEnabled is returned when custom Mullvad support is not enabled.
	ErrNotEnabled = errors.New("custom mullvad support not enabled")
)

// Server represents a Mullvad WireGuard server.
type Server struct {
	Hostname    string         // "us-nyc-wg-001"
	IPv4        netip.Addr     // Server's IPv4 address
	IPv6        netip.Addr     // Server's IPv6 address
	PublicKey   key.NodePublic // Server's WireGuard public key
	Port        uint16         // WireGuard port (usually 51820)
	CountryCode string         // ISO 3166-1 alpha-2 ("us")
	CountryName string         // "USA"
	CityCode    string         // "nyc"
	CityName    string         // "New York City"
	Active      bool           // Whether the server is currently active
	Owned       bool           // Whether Mullvad owns this server
}

// AccountStatus contains account information.
type AccountStatus struct {
	Expiry    time.Time
	DaysLeft  int
	IsExpired bool
}

// DeviceInfo represents a registered device.
type DeviceInfo struct {
	ID          string
	PublicKey   key.NodePublic
	IPv4Address netip.Addr
	IPv6Address netip.Addr
	Created     time.Time
}

// API request types for JSON marshaling.
type (
	tokenRequest struct {
		AccountNumber string `json:"account_number"`
	}
	deviceRegisterRequest struct {
		Pubkey    string `json:"pubkey"`
		HijackDNS bool   `json:"hijack_dns"`
	}
	deviceRotateKeyRequest struct {
		Pubkey string `json:"pubkey"`
	}
)

// Client handles communication with the Mullvad API.
type Client struct {
	httpClient *http.Client
	logf       logger.Logf
	apiBase    string

	mu          sync.Mutex
	accountNum  string
	accessToken string
	tokenExpiry time.Time
	deviceID    string
	deviceInfo  *DeviceInfo

	// Cached data
	servers        []Server
	serversFetched time.Time
}

// DialContextFunc is a function that dials a network connection.
// This allows the caller to provide a custom dialer that bypasses the Tailscale tunnel.
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// NewClient creates a new Mullvad API client.
// dialFunc is used for HTTP connections (e.g., to bypass Tailscale tunnel).
// dnsResolver is used for DNS lookups (to bypass MagicDNS during bootstrap).
// If dialFunc is nil, the default system dialer is used.
// If dnsResolver is nil, DNS lookups use the system resolver directly.
func NewClient(accountNumber string, logf logger.Logf, dialFunc DialContextFunc, dnsResolver *dnscache.Resolver) (*Client, error) {
	if !CustomMullvadEnabled() {
		return nil, ErrNotEnabled
	}
	if !isValidAccountNumber(accountNumber) {
		return nil, ErrInvalidAccount
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}
	if dialFunc != nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if dnsResolver != nil {
			// Wrap dialFunc with DNS caching that bypasses MagicDNS.
			// This solves the bootstrap problem where MagicDNS routes to Mullvad DNS
			// which is unreachable before the Mullvad tunnel is established.
			tr.DialContext = dnscache.Dialer(netx.DialFunc(dialFunc), dnsResolver)
		} else {
			tr.DialContext = dialFunc
		}
		httpClient.Transport = tr
	}

	return &Client{
		httpClient: httpClient,
		logf:       logf,
		apiBase:    defaultAPIBase,
		accountNum: accountNumber,
	}, nil
}

// isValidAccountNumber checks if the account number is valid (16 digits).
func isValidAccountNumber(num string) bool {
	if len(num) != 16 {
		return false
	}
	for _, c := range num {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// tokenResponse represents the response from the token endpoint.
type tokenResponse struct {
	AccessToken string    `json:"access_token"`
	Expiry      time.Time `json:"expiry"`
}

// Authenticate obtains an access token from Mullvad.
func (c *Client) Authenticate(ctx context.Context) error {
	// Fast path: check if we already have a valid token.
	c.mu.Lock()
	if c.accessToken != "" && time.Now().Add(tokenRefreshMargin).Before(c.tokenExpiry) {
		c.mu.Unlock()
		return nil
	}
	// Copy values needed for the request while holding the lock.
	accountNum := c.accountNum
	apiBase := c.apiBase
	c.mu.Unlock()

	// Do HTTP request without holding the lock to avoid blocking concurrent operations.
	reqBodyJSON, err := json.Marshal(tokenRequest{AccountNumber: accountNum})
	if err != nil {
		return fmt.Errorf("marshaling auth request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", apiBase+"/auth/v1/token", bytes.NewReader(reqBodyJSON))
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusNotFound {
		return ErrInvalidAccount
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		return fmt.Errorf("auth failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("decoding auth response: %w", err)
	}

	// Reacquire lock to update state.
	c.mu.Lock()
	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = tokenResp.Expiry
	c.mu.Unlock()

	c.logf("mullvad: authenticated, token expires at %v", tokenResp.Expiry)
	return nil
}

// accountResponse represents the response from the public account endpoint.
// Endpoint: GET https://api.mullvad.net/public/accounts/v1/{account}
// Example response: {"id":"1234567890123456","expiry":"2026-02-01T20:01:32+00:00"}
type accountResponse struct {
	ID     string    `json:"id"`
	Expiry time.Time `json:"expiry"`
}

// GetAccountStatus checks account expiry using the public API endpoint.
func (c *Client) GetAccountStatus(ctx context.Context) (*AccountStatus, error) {
	// Use the public API endpoint that doesn't require auth
	req, err := http.NewRequestWithContext(ctx, "GET", c.apiBase+"/public/accounts/v1/"+c.accountNum, nil)
	if err != nil {
		return nil, fmt.Errorf("creating account status request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("account status request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrInvalidAccount
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		return nil, fmt.Errorf("account status failed with status %d: %s", resp.StatusCode, string(body))
	}

	var accResp accountResponse
	if err := json.NewDecoder(resp.Body).Decode(&accResp); err != nil {
		return nil, fmt.Errorf("decoding account response: %w", err)
	}

	now := time.Now()
	daysLeft := int(accResp.Expiry.Sub(now).Hours() / 24)
	if daysLeft < 0 {
		daysLeft = 0
	}

	return &AccountStatus{
		Expiry:    accResp.Expiry,
		DaysLeft:  daysLeft,
		IsExpired: now.After(accResp.Expiry),
	}, nil
}

// deviceResponse represents a device from the API.
type deviceResponse struct {
	ID          string `json:"id"`
	Pubkey      string `json:"pubkey"`
	IPv4Address string `json:"ipv4_address"`
	IPv6Address string `json:"ipv6_address"`
	Created     string `json:"created"`
}

// RegisterDevice registers a WireGuard public key with Mullvad.
func (c *Client) RegisterDevice(ctx context.Context, pubkey key.NodePublic) (*DeviceInfo, error) {
	if err := c.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	c.mu.Lock()
	token := c.accessToken
	c.mu.Unlock()

	// Encode the public key as base64
	pubkeyBytes := pubkey.Raw32()
	pubkeyB64 := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	reqBodyJSON, err := json.Marshal(deviceRegisterRequest{Pubkey: pubkeyB64, HijackDNS: false})
	if err != nil {
		return nil, fmt.Errorf("marshaling register request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiBase+"/accounts/v1/devices", bytes.NewReader(reqBodyJSON))
	if err != nil {
		return nil, fmt.Errorf("creating register request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusConflict {
		// Device already registered, try to find it
		return c.findExistingDevice(ctx, pubkey)
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, ErrDeviceLimitReached
	}
	if resp.StatusCode == http.StatusBadRequest {
		// Check if it's a "pubkey already in use" error
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		if strings.Contains(string(body), "PUBKEY_IN_USE") || strings.Contains(string(body), "already in use") {
			// Key already registered, try to find it
			c.logf("mullvad: key already registered, looking up existing device")
			return c.findExistingDevice(ctx, pubkey)
		}
		return nil, fmt.Errorf("register failed with status %d: %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		return nil, fmt.Errorf("register failed with status %d: %s", resp.StatusCode, string(body))
	}

	var devResp deviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&devResp); err != nil {
		return nil, fmt.Errorf("decoding register response: %w", err)
	}

	info, err := parseDeviceResponse(&devResp)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.deviceID = info.ID
	c.deviceInfo = info
	c.mu.Unlock()

	c.logf("mullvad: registered device %s with IPv4 %v", info.ID, info.IPv4Address)
	return info, nil
}

func parseDeviceResponse(resp *deviceResponse) (*DeviceInfo, error) {
	// Parse public key
	pubkeyBytes, err := base64.StdEncoding.DecodeString(resp.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("decoding pubkey: %w", err)
	}
	if len(pubkeyBytes) != 32 {
		return nil, fmt.Errorf("invalid pubkey length: %d", len(pubkeyBytes))
	}
	pubkey := key.NodePublicFromRaw32(mem.B(pubkeyBytes))

	// Parse IPv4 address (strip the /32 suffix if present)
	ipv4Str := strings.TrimSuffix(resp.IPv4Address, "/32")
	ipv4, err := netip.ParseAddr(ipv4Str)
	if err != nil {
		return nil, fmt.Errorf("parsing IPv4: %w", err)
	}

	// Parse IPv6 address (strip the /128 suffix if present)
	ipv6Str := strings.TrimSuffix(resp.IPv6Address, "/128")
	ipv6, err := netip.ParseAddr(ipv6Str)
	if err != nil {
		return nil, fmt.Errorf("parsing IPv6: %w", err)
	}

	return &DeviceInfo{
		ID:          resp.ID,
		PublicKey:   pubkey,
		IPv4Address: ipv4,
		IPv6Address: ipv6,
	}, nil
}

// findExistingDevice finds a device by its public key.
func (c *Client) findExistingDevice(ctx context.Context, pubkey key.NodePublic) (*DeviceInfo, error) {
	devices, err := c.ListDevices(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing devices: %w", err)
	}

	pubkeyBytes := pubkey.Raw32()
	pubkeyB64 := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	for _, dev := range devices {
		devKeyBytes := dev.PublicKey.Raw32()
		devKeyB64 := base64.StdEncoding.EncodeToString(devKeyBytes[:])
		if devKeyB64 == pubkeyB64 {
			c.mu.Lock()
			c.deviceID = dev.ID
			c.deviceInfo = dev
			c.mu.Unlock()
			return dev, nil
		}
	}

	return nil, fmt.Errorf("device with key not found")
}

// ListDevices returns all devices registered to the account.
func (c *Client) ListDevices(ctx context.Context) ([]*DeviceInfo, error) {
	if err := c.Authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	c.mu.Lock()
	token := c.accessToken
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, "GET", c.apiBase+"/accounts/v1/devices", nil)
	if err != nil {
		return nil, fmt.Errorf("creating list devices request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list devices request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		return nil, fmt.Errorf("list devices failed with status %d: %s", resp.StatusCode, string(body))
	}

	var devicesResp []deviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&devicesResp); err != nil {
		return nil, fmt.Errorf("decoding devices response: %w", err)
	}

	devices := make([]*DeviceInfo, 0, len(devicesResp))
	for _, d := range devicesResp {
		info, err := parseDeviceResponse(&d)
		if err != nil {
			c.logf("mullvad: skipping device %s: %v", d.ID, err)
			continue
		}
		devices = append(devices, info)
	}

	return devices, nil
}

// relayResponse represents a relay from the /public/relays/wireguard/v2/ API.
// Example: {"hostname":"us-nyc-wg-001","location":"us-nyc","active":true,"owned":false,
//           "provider":"M247","ipv4_addr_in":"146.70.198.66","include_in_country":true,
//           "weight":100,"public_key":"TUCaQc26/R6AGpkDUr8A8ytUs/e5+UVlIVujbuBwlzI=",
//           "ipv6_addr_in":"2a0d:5600:9:c::f001"}
type relayResponse struct {
	Hostname         string `json:"hostname"`
	Location         string `json:"location"`
	Active           bool   `json:"active"`
	Owned            bool   `json:"owned"`
	Provider         string `json:"provider"`
	IPv4AddrIn       string `json:"ipv4_addr_in"`
	IPv6AddrIn       string `json:"ipv6_addr_in"`
	PublicKey        string `json:"public_key"`
	IncludeInCountry bool   `json:"include_in_country"`
	Weight           int    `json:"weight"`
}

// locationInfo represents a location from the relay list.
type locationInfo struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// relayListResponse represents the response from /public/relays/wireguard/v2/.
type relayListResponse struct {
	Locations map[string]locationInfo `json:"locations"`
	WireGuard struct {
		Relays []relayResponse `json:"relays"`
	} `json:"wireguard"`
}

// GetServers fetches the list of available Mullvad WireGuard servers.
func (c *Client) GetServers(ctx context.Context) ([]Server, error) {
	c.mu.Lock()
	// Check cache
	if len(c.servers) > 0 && time.Since(c.serversFetched) < serverCacheExpiry {
		servers := c.servers
		c.mu.Unlock()
		return servers, nil
	}
	c.mu.Unlock()

	// Fetch the relay list from the v2 API
	req, err := http.NewRequestWithContext(ctx, "GET", c.apiBase+"/public/relays/wireguard/v2/", nil)
	if err != nil {
		return nil, fmt.Errorf("creating servers request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("servers request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		return nil, fmt.Errorf("servers request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var relayList relayListResponse
	if err := json.NewDecoder(resp.Body).Decode(&relayList); err != nil {
		return nil, fmt.Errorf("decoding servers response: %w", err)
	}

	servers := make([]Server, 0, len(relayList.WireGuard.Relays))
	for _, r := range relayList.WireGuard.Relays {
		// Parse IPv4
		ipv4, err := netip.ParseAddr(r.IPv4AddrIn)
		if err != nil {
			c.logf("mullvad: skipping server %s: invalid IPv4: %v", r.Hostname, err)
			continue
		}

		// Parse IPv6
		var ipv6 netip.Addr
		if r.IPv6AddrIn != "" {
			ipv6, err = netip.ParseAddr(r.IPv6AddrIn)
			if err != nil {
				c.logf("mullvad: server %s has invalid IPv6: %v", r.Hostname, err)
				// Don't skip, IPv6 is optional
			}
		}

		// Parse public key
		pubkeyBytes, err := base64.StdEncoding.DecodeString(r.PublicKey)
		if err != nil {
			c.logf("mullvad: skipping server %s: invalid pubkey: %v", r.Hostname, err)
			continue
		}
		if len(pubkeyBytes) != 32 {
			c.logf("mullvad: skipping server %s: wrong pubkey length", r.Hostname)
			continue
		}
		pubkey := key.NodePublicFromRaw32(mem.B(pubkeyBytes))

		// Get location info
		loc := relayList.Locations[r.Location]
		// Location code format is like "us-nyc", split to get country and city codes
		countryCode := ""
		cityCode := ""
		if parts := strings.SplitN(r.Location, "-", 2); len(parts) == 2 {
			countryCode = parts[0]
			cityCode = parts[1]
		}

		servers = append(servers, Server{
			Hostname:    r.Hostname,
			IPv4:        ipv4,
			IPv6:        ipv6,
			PublicKey:   pubkey,
			Port:        defaultWireGuardPort,
			CountryCode: countryCode,
			CountryName: loc.Country,
			CityCode:    cityCode,
			CityName:    loc.City,
			Active:      r.Active,
			Owned:       r.Owned,
		})
	}

	c.mu.Lock()
	c.servers = servers
	c.serversFetched = time.Now()
	c.mu.Unlock()

	c.logf("mullvad: fetched %d WireGuard servers", len(servers))
	return servers, nil
}

// GetDeviceInfo returns the current device info.
func (c *Client) GetDeviceInfo() *DeviceInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deviceInfo
}

// AccountNumber returns the account number.
func (c *Client) AccountNumber() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accountNum
}

// MaskedAccountNumber returns the account number with middle digits masked.
func (c *Client) MaskedAccountNumber() string {
	c.mu.Lock()
	num := c.accountNum
	c.mu.Unlock()

	if len(num) != 16 {
		return "invalid"
	}
	return num[:4] + "********" + num[12:]
}

// RotateKey rotates the registered WireGuard key.
func (c *Client) RotateKey(ctx context.Context, newPubkey key.NodePublic) error {
	if err := c.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.mu.Lock()
	token := c.accessToken
	deviceID := c.deviceID
	c.mu.Unlock()

	if deviceID == "" {
		return fmt.Errorf("no device registered")
	}

	pubkeyBytes := newPubkey.Raw32()
	pubkeyB64 := base64.StdEncoding.EncodeToString(pubkeyBytes[:])

	reqBodyJSON, err := json.Marshal(deviceRotateKeyRequest{Pubkey: pubkeyB64})
	if err != nil {
		return fmt.Errorf("marshaling rotate key request: %w", err)
	}
	endpoint := fmt.Sprintf("%s/accounts/v1/devices/%s/pubkey", c.apiBase, url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, "PUT", endpoint, bytes.NewReader(reqBodyJSON))
	if err != nil {
		return fmt.Errorf("creating rotate key request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rotate key request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		return fmt.Errorf("rotate key failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.logf("mullvad: rotated key for device %s", deviceID)
	return nil
}

// RemoveDevice removes the registered device.
func (c *Client) RemoveDevice(ctx context.Context) error {
	if err := c.Authenticate(ctx); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	c.mu.Lock()
	token := c.accessToken
	deviceID := c.deviceID
	c.mu.Unlock()

	if deviceID == "" {
		return nil // Nothing to remove
	}

	endpoint := fmt.Sprintf("%s/accounts/v1/devices/%s", c.apiBase, url.PathEscape(deviceID))
	req, err := http.NewRequestWithContext(ctx, "DELETE", endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating remove device request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("remove device request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
		return fmt.Errorf("remove device failed with status %d: %s", resp.StatusCode, string(body))
	}

	c.mu.Lock()
	c.deviceID = ""
	c.deviceInfo = nil
	c.mu.Unlock()

	c.logf("mullvad: removed device")
	return nil
}

// VerifyConnection checks if traffic is routing through Mullvad.
func (c *Client) VerifyConnection(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://am.i.mullvad.net/connected", nil)
	if err != nil {
		return false, fmt.Errorf("creating verify request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("verify request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponseSize))
	if err != nil {
		return false, fmt.Errorf("reading verify response: %w", err)
	}

	return strings.Contains(string(body), "You are connected to Mullvad"), nil
}
