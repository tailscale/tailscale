// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/health"
	"tailscale.com/ipn/ipnlocal/mullvad"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/dns/publicdns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// customMullvadState holds the state for the custom Mullvad integration.
// All fields are protected by LocalBackend.mu.
type customMullvadState struct {
	// client is the Mullvad API client
	client *mullvad.Client

	// peers are the injected Mullvad servers as tailcfg.Node entries
	peers []*tailcfg.Node

	// deviceInfo contains the registered device info from Mullvad
	deviceInfo *mullvad.DeviceInfo

	// lastRefresh is when the server list was last refreshed
	lastRefresh time.Time

	// accountStatus contains the last known account status
	accountStatus *mullvad.AccountStatus
}


// getOrCreateCustomMullvadStateLocked returns the custom Mullvad state,
// creating it if necessary. Must be called with b.mu held.
func (b *LocalBackend) getOrCreateCustomMullvadStateLocked() *customMullvadState {
	if b.customMullvadState == nil {
		b.customMullvadState = &customMullvadState{}
	}
	return b.customMullvadState
}

// clearCustomMullvadLocked removes the custom Mullvad configuration.
// Must be called with b.mu held.
func (b *LocalBackend) clearCustomMullvadLocked() {
	if b.customMullvadState == nil {
		return
	}

	// Clear health warnings
	b.clearCustomMullvadWarnings()

	// Clear custom peers from nodeBackend
	b.currentNode().SetCustomPeers(nil)

	// Best-effort: deregister device from Mullvad to free up the device slot.
	if client := b.customMullvadState.client; client != nil {
		go func() {
			ctx, cancel := context.WithTimeout(b.ctx, 10*time.Second)
			defer cancel()
			if err := client.RemoveDevice(ctx); err != nil {
				b.logf("mullvad: failed to remove device: %v", err)
			} else {
				b.logf("mullvad: removed device from Mullvad account")
			}
		}()
	}

	b.customMullvadState = nil
	b.logf("mullvad: cleared custom Mullvad configuration")
}


// mullvadDeviceIDStateKey is the state key for storing the custom Mullvad device ID.
const mullvadDeviceIDStateKey = "custom-mullvad-device-id"

// saveMullvadDeviceIDLocked saves the Mullvad device ID to storage.
// Must be called with b.mu held.
func (b *LocalBackend) saveMullvadDeviceIDLocked(deviceID string) error {
	if err := b.pm.WriteState(mullvadDeviceIDStateKey, []byte(deviceID)); err != nil {
		return fmt.Errorf("writing device ID: %w", err)
	}
	return nil
}

// loadMullvadDeviceIDLocked loads the Mullvad device ID from storage.
// Must be called with b.mu held.
func (b *LocalBackend) loadMullvadDeviceIDLocked() (string, error) {
	deviceID, err := b.pm.Store().ReadState(mullvadDeviceIDStateKey)
	if err != nil {
		return "", err
	}
	return string(deviceID), nil
}

// customMullvadServerToNode converts a Mullvad server to a tailcfg.Node.
func (b *LocalBackend) customMullvadServerToNode(server mullvad.Server, deviceInfo *mullvad.DeviceInfo) *tailcfg.Node {
	// Generate a stable node ID from the hostname
	h := sha256.Sum256([]byte("custom-mullvad-" + server.Hostname))
	nodeID := tailcfg.NodeID(binary.BigEndian.Uint64(h[:8]))

	endpoints := make([]netip.AddrPort, 0, 2)
	if server.IPv4.IsValid() {
		endpoints = append(endpoints, netip.AddrPortFrom(server.IPv4, server.Port))
	}
	if server.IPv6.IsValid() {
		endpoints = append(endpoints, netip.AddrPortFrom(server.IPv6, server.Port))
	}

	// Use the server's public IPs as addresses for display purposes.
	// This gives each server a unique IP in the exit-node list.
	addresses := make([]netip.Prefix, 0, 2)
	if server.IPv4.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(server.IPv4, 32))
	}
	if server.IPv6.IsValid() {
		addresses = append(addresses, netip.PrefixFrom(server.IPv6, 128))
	}

	// AllowedIPs for exit node: 0.0.0.0/0 and ::/0
	allowedIPs := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}

	// Mullvad DNS servers
	dnsResolvers := []*dnstype.Resolver{
		{Addr: "10.64.0.1"}, // Mullvad internal DNS
	}

	node := &tailcfg.Node{
		ID:       nodeID,
		StableID: tailcfg.StableNodeID("custom-mullvad-" + server.Hostname),
		Name:     server.Hostname + ".mullvad.custom.",

		Key:             server.PublicKey,
		IsWireGuardOnly: true,

		Endpoints:  endpoints,
		AllowedIPs: allowedIPs,
		Addresses:  addresses,

		Hostinfo: (&tailcfg.Hostinfo{
			Location: &tailcfg.Location{
				Country:     server.CountryName,
				CountryCode: strings.ToUpper(server.CountryCode),
				City:        server.CityName,
				CityCode:    strings.ToUpper(server.CityCode),
				Priority:    50, // Lower than Tailscale-managed Mullvad
			},
		}).View(),

		ExitNodeDNSResolvers: dnsResolvers,

		CapMap: tailcfg.NodeCapMap{
			tailcfg.NodeAttrSuggestExitNode: nil,
			tailcfg.NodeAttrCustomMullvad:   nil,
		},
	}

	// Set masquerade addresses so that nmcfg.WGCfg() configures WireGuard
	// to masquerade traffic as the Mullvad-assigned IPs. Without this,
	// Mullvad servers would see our Tailscale IP instead of the IP they
	// assigned to us, and drop the traffic.
	if deviceInfo != nil {
		if v4 := deviceInfo.IPv4Address; v4.IsValid() {
			node.SelfNodeV4MasqAddrForThisPeer = &v4
		}
		if v6 := deviceInfo.IPv6Address; v6.IsValid() {
			node.SelfNodeV6MasqAddrForThisPeer = &v6
		}
	}

	return node
}


func (b *LocalBackend) updateCustomMullvadHealthWarningsLocked(status *mullvad.AccountStatus) {
	if status == nil {
		return
	}

	// Clear existing warnings first
	b.clearCustomMullvadWarnings()

	if status.IsExpired {
		b.setCustomMullvadExpiredWarning(status)
	} else if status.DaysLeft <= 7 {
		b.setCustomMullvadExpiringWarning(status)
	}
}

func (b *LocalBackend) setCustomMullvadExpiringWarning(status *mullvad.AccountStatus) {
	b.health.SetUnhealthy(health.CustomMullvadExpiringWarnable, health.Args{
		health.ArgDaysRemaining: strconv.Itoa(status.DaysLeft),
	})
}

func (b *LocalBackend) setCustomMullvadExpiredWarning(status *mullvad.AccountStatus) {
	b.health.SetUnhealthy(health.CustomMullvadExpiredWarnable, health.Args{
		health.ArgExpiryDate: status.Expiry.Format("2006-01-02"),
	})
}

func (b *LocalBackend) setCustomMullvadAuthFailedWarning(err error) {
	b.health.SetUnhealthy(health.CustomMullvadAuthFailedWarnable, health.Args{
		health.ArgError: err.Error(),
	})
}

func (b *LocalBackend) clearCustomMullvadAuthFailedWarning() {
	b.health.SetHealthy(health.CustomMullvadAuthFailedWarnable)
}

func (b *LocalBackend) clearCustomMullvadWarnings() {
	b.health.SetHealthy(health.CustomMullvadExpiringWarnable)
	b.health.SetHealthy(health.CustomMullvadExpiredWarnable)
	b.health.SetHealthy(health.CustomMullvadAuthFailedWarnable)
}


// CustomMullvadStatus returns information about the custom Mullvad configuration.
type CustomMullvadStatus struct {
	Configured    bool
	AccountExpiry time.Time
	DaysRemaining int
	ServerCount   int
	DeviceIPv4    netip.Addr
	DeviceIPv6    netip.Addr
	LastRefresh   time.Time
}

// GetCustomMullvadStatus returns the current custom Mullvad status.
// Thread-safe.
func (b *LocalBackend) GetCustomMullvadStatus() CustomMullvadStatus {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.customMullvadState == nil || b.customMullvadState.client == nil {
		return CustomMullvadStatus{}
	}

	state := b.customMullvadState
	status := CustomMullvadStatus{
		Configured:  true,
		ServerCount: len(state.peers),
		LastRefresh: state.lastRefresh,
	}

	if state.accountStatus != nil {
		status.AccountExpiry = state.accountStatus.Expiry
		status.DaysRemaining = state.accountStatus.DaysLeft
	}

	if state.deviceInfo != nil {
		status.DeviceIPv4 = state.deviceInfo.IPv4Address
		status.DeviceIPv6 = state.deviceInfo.IPv6Address
	}

	return status
}

// ConfigureCustomMullvad configures the custom Mullvad account.
// It releases b.mu during HTTP calls to avoid blocking the entire LocalBackend.
func (b *LocalBackend) ConfigureCustomMullvad(ctx context.Context, accountNumber string) error {
	if !mullvad.CustomMullvadEnabled() {
		return mullvad.ErrNotEnabled
	}

	// Handle clearing under lock (quick, no HTTP).
	if accountNumber == "" {
		b.mu.Lock()
		b.clearCustomMullvadLocked()
		b.mu.Unlock()
		return nil
	}

	// Phase 1: Under lock, create/reuse client and snapshot state needed for HTTP calls.
	b.mu.Lock()
	state := b.getOrCreateCustomMullvadStateLocked()
	if state.client == nil || state.client.AccountNumber() != accountNumber {
		dnsResolver := b.createMullvadBootstrapDNSResolver()
		client, err := mullvad.NewClient(accountNumber, b.logf, b.dialer.SystemDial, dnsResolver)
		if err != nil {
			b.mu.Unlock()
			return fmt.Errorf("creating Mullvad client: %w", err)
		}
		state.client = client
	}
	client := state.client
	pubKey := b.pm.CurrentPrefs().Persist().PrivateNodeKey().Public()
	b.mu.Unlock()

	// Phase 2: HTTP calls without holding b.mu.
	if err := client.Authenticate(ctx); err != nil {
		b.setCustomMullvadAuthFailedWarning(err)
		return fmt.Errorf("authenticating with Mullvad: %w", err)
	}
	b.clearCustomMullvadAuthFailedWarning()

	status, err := client.GetAccountStatus(ctx)
	if err != nil {
		b.setCustomMullvadAuthFailedWarning(err)
		return fmt.Errorf("checking account status: %w", err)
	}

	if status.IsExpired {
		b.setCustomMullvadExpiredWarning(status)
		return mullvad.ErrAccountExpired
	}

	deviceInfo, err := client.RegisterDevice(ctx, pubKey)
	if err != nil {
		return fmt.Errorf("registering with Mullvad: %w", err)
	}

	servers, err := client.GetServers(ctx)
	if err != nil {
		return fmt.Errorf("fetching Mullvad servers: %w", err)
	}

	// Phase 3: Re-acquire lock and update state with results.
	b.mu.Lock()
	defer b.mu.Unlock()

	// Verify the node key hasn't changed while we were doing HTTP calls.
	// If it changed (e.g., re-auth), the device we registered with Mullvad
	// has the wrong key and we need to re-register.
	currentPubKey := b.pm.CurrentPrefs().Persist().PrivateNodeKey().Public()
	if currentPubKey != pubKey {
		b.logf("mullvad: node key changed during configuration, will re-register on next auth")
		// Don't fail — save what we have. The enterStateLocked path
		// will trigger re-registration when the new key is stable.
	}

	state = b.getOrCreateCustomMullvadStateLocked()
	state.accountStatus = status
	state.deviceInfo = deviceInfo

	b.updateCustomMullvadHealthWarningsLocked(status)

	// Save device ID for future lookups.
	existingDeviceID, _ := b.loadMullvadDeviceIDLocked()
	if existingDeviceID != deviceInfo.ID {
		if err := b.saveMullvadDeviceIDLocked(deviceInfo.ID); err != nil {
			b.logf("mullvad: warning: failed to save device ID: %v", err)
		}
	}

	// Convert servers to tailcfg.Node entries.
	peers := make([]*tailcfg.Node, 0, len(servers))
	for _, server := range servers {
		if !server.Active {
			continue
		}
		peers = append(peers, b.customMullvadServerToNode(server, deviceInfo))
	}

	state.peers = peers
	state.lastRefresh = time.Now()
	b.injectCustomMullvadPeersLocked()

	b.logf("mullvad: configured %d exit nodes from personal account", len(peers))
	return nil
}

// RefreshCustomMullvad refreshes the custom Mullvad configuration.
// It releases b.mu during HTTP calls to avoid blocking the entire LocalBackend.
func (b *LocalBackend) RefreshCustomMullvad(ctx context.Context) error {
	// Phase 1: Under lock, grab the client reference.
	b.mu.Lock()
	if b.customMullvadState == nil || b.customMullvadState.client == nil {
		b.mu.Unlock()
		return nil
	}
	client := b.customMullvadState.client
	deviceInfo := b.customMullvadState.deviceInfo
	b.mu.Unlock()

	// Phase 2: HTTP calls without holding b.mu.
	status, err := client.GetAccountStatus(ctx)
	if err != nil {
		b.setCustomMullvadAuthFailedWarning(err)
		return fmt.Errorf("checking account status: %w", err)
	}
	b.clearCustomMullvadAuthFailedWarning()

	if status.IsExpired {
		b.mu.Lock()
		b.updateCustomMullvadHealthWarningsLocked(status)
		b.mu.Unlock()
		return mullvad.ErrAccountExpired
	}

	servers, err := client.GetServers(ctx)
	if err != nil {
		return fmt.Errorf("fetching Mullvad servers: %w", err)
	}

	// Phase 3: Re-acquire lock and update state.
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.customMullvadState == nil {
		return nil // cleared while we were fetching
	}

	b.customMullvadState.accountStatus = status
	b.updateCustomMullvadHealthWarningsLocked(status)

	peers := make([]*tailcfg.Node, 0, len(servers))
	for _, server := range servers {
		if !server.Active {
			continue
		}
		peers = append(peers, b.customMullvadServerToNode(server, deviceInfo))
	}

	b.customMullvadState.peers = peers
	b.customMullvadState.lastRefresh = time.Now()
	b.injectCustomMullvadPeersLocked()

	b.logf("mullvad: refreshed server list, %d exit nodes available", len(peers))
	return nil
}

// injectCustomMullvadPeersLocked updates the nodeBackend with custom Mullvad peers
// so they are included in peer lookups and WireGuard configuration.
// It also notifies magicsock about the updated peer set so that ParseEndpoint
// can find the custom peers when WireGuard needs to send to them.
// Must be called with b.mu held.
func (b *LocalBackend) injectCustomMullvadPeersLocked() {
	cn := b.currentNode()
	if b.customMullvadState == nil || len(b.customMullvadState.peers) == 0 {
		cn.SetCustomPeers(nil)
	} else {
		peerViews := make([]tailcfg.NodeView, len(b.customMullvadState.peers))
		for i, p := range b.customMullvadState.peers {
			peerViews[i] = p.View()
		}
		cn.SetCustomPeers(peerViews)
	}

	// Notify magicsock about the combined peer set (control + custom).
	// This is critical: magicsock needs to know about custom peers for
	// ParseEndpoint to work when WireGuard sends packets to them.
	nm := cn.netMapWithPeers()
	if ms, ok := b.sys.MagicSock.GetOK(); ok && nm != nil {
		ms.SetNetworkMap(nm.SelfNode, nm.Peers)
	}
}

// createMullvadBootstrapDNSResolver creates a DNS resolver for Mullvad API calls
// that bypasses MagicDNS by using public DoH servers as a fallback.
// This solves the bootstrap problem where MagicDNS routes to Mullvad DNS
// which is unreachable before the Mullvad tunnel is established.
//
// Pattern: Same as net/dns/resolver/forwarder.go getKnownDoHClientForProvider()
func (b *LocalBackend) createMullvadBootstrapDNSResolver() *dnscache.Resolver {
	return &dnscache.Resolver{
		Forward:          dnscache.Get().Forward,
		UseLastGood:      true,
		LookupIPFallback: b.resolveMullvadAPIViaDoH,
		Logf:             b.logf,
	}
}

// resolveMullvadAPIViaDoH resolves hostnames using public DoH providers.
// Uses the existing publicdns package to get known DoH provider IPs,
// avoiding hardcoded DNS servers in this code.
// Uses SystemDial to ensure the DoH request bypasses the Tailscale tunnel.
func (b *LocalBackend) resolveMullvadAPIViaDoH(ctx context.Context, host string) ([]netip.Addr, error) {
	// Try multiple DoH providers in order (same providers used by net/dns/resolver/forwarder.go)
	dohProviders := []string{
		"https://cloudflare-dns.com/dns-query",
		"https://dns.google/dns-query",
		"https://dns.quad9.net/dns-query",
	}

	var lastErr error
	for _, dohBase := range dohProviders {
		addrs, err := b.resolveViaDoHProvider(ctx, host, dohBase)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
		lastErr = err
		b.logf("mullvad: DoH provider %s failed: %v", dohBase, err)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all DoH providers failed, last error: %w", lastErr)
	}
	return nil, errors.New("no DoH providers available")
}

// resolveViaDoHProvider resolves a hostname using a specific DoH provider.
// Uses publicdns.DoHIPsOfBase() to get known IPs for the provider.
func (b *LocalBackend) resolveViaDoHProvider(ctx context.Context, host, dohBase string) ([]netip.Addr, error) {
	// Get known IPs for this DoH provider from publicdns package.
	// This avoids hardcoding IPs - we use Tailscale's existing known DoH provider list.
	allIPs := publicdns.DoHIPsOfBase(dohBase)
	if len(allIPs) == 0 {
		return nil, fmt.Errorf("no known IPs for DoH provider %s", dohBase)
	}

	// Parse the DoH URL to get the hostname
	dohURL, err := url.Parse(dohBase)
	if err != nil {
		return nil, err
	}

	// Create HTTP client that dials the DoH provider directly by IP.
	// Pattern from net/dns/resolver/forwarder.go:438-442
	dohResolver := &dnscache.Resolver{
		SingleHost:             dohURL.Hostname(),
		SingleHostStaticResult: allIPs,
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = dnscache.Dialer(b.dialer.SystemDial, dohResolver)
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	// Build DNS query for host (A and AAAA records)
	addrs, err := b.doDoHQuery(ctx, hc, dohBase, host, dnsmessage.TypeA)
	if err != nil {
		b.logf("mullvad: DoH A query to %s for %s failed: %v", dohBase, host, err)
	}

	// Also try AAAA
	addrs6, err6 := b.doDoHQuery(ctx, hc, dohBase, host, dnsmessage.TypeAAAA)
	if err6 == nil {
		addrs = append(addrs, addrs6...)
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses returned from %s for %s", dohBase, host)
	}
	return addrs, nil
}

// doDoHQuery performs a single DoH query for the given record type.
func (b *LocalBackend) doDoHQuery(ctx context.Context, hc *http.Client, dohBase, host string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	// Build DNS query packet
	var msg dnsmessage.Message
	msg.Header.ID = uint16(time.Now().UnixNano())
	msg.Header.RecursionDesired = true
	msg.Questions = []dnsmessage.Question{
		{Name: dnsmessage.MustNewName(host + "."), Type: qtype, Class: dnsmessage.ClassINET},
	}
	packet, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	// Send DoH request (RFC 8484)
	req, err := http.NewRequestWithContext(ctx, "POST", dohBase, bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DoH returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse DNS response
	var respMsg dnsmessage.Message
	if err := respMsg.Unpack(body); err != nil {
		return nil, err
	}

	var addrs []netip.Addr
	for _, ans := range respMsg.Answers {
		switch r := ans.Body.(type) {
		case *dnsmessage.AResource:
			addrs = append(addrs, netip.AddrFrom4(r.A))
		case *dnsmessage.AAAAResource:
			addrs = append(addrs, netip.AddrFrom16(r.AAAA))
		}
	}
	return addrs, nil
}
