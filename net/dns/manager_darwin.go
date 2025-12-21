// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"go4.org/mem"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/mak"
	"tailscale.com/util/syspolicy/policyclient"
)

// NewOSConfigurator creates a new OS configurator.
//
// The health tracker, bus and the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logf logger.Logf, _ *health.Tracker, _ *eventbus.Bus, _ policyclient.Client, _ *controlknobs.Knobs, ifName string) (OSConfigurator, error) {
	return &darwinConfigurator{logf: logf, ifName: ifName}, nil
}

// darwinConfigurator is the tailscaled-on-macOS DNS OS configurator that
// maintains the Split DNS nameserver entries pointing MagicDNS DNS suffixes
// to 100.100.100.100 using the macOS /etc/resolver/$SUFFIX files.
//
// On macOS CLI (tailscaled without Network Extension), packets to 100.100.100.100
// don't reach the TUN device because mDNSResponder mediates all DNS. To work around
// this, we run a local DNS listener on 127.0.0.1 and point the /etc/resolver files
// to that address instead. We use a non-standard port (preferring 5533) because
// macOS intercepts port 53 at a low level before it reaches userspace listeners.
type darwinConfigurator struct {
	logf   logger.Logf
	ifName string

	mu           sync.Mutex
	resolver     *resolver.Resolver // set by SetResolver; used to handle local DNS queries
	listener     *net.UDPConn       // local DNS listener on 127.0.0.1
	listenerPort int                // actual port the listener is bound to
	ctx          context.Context    // for listener goroutine
	cancel       context.CancelFunc // cancels listener goroutine
}

// SetResolver sets the DNS resolver to use for handling local DNS queries.
// This must be called before SetDNS for the local DNS listener to work.
func (c *darwinConfigurator) SetResolver(r *resolver.Resolver) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resolver = r
}

func (c *darwinConfigurator) Close() error {
	c.mu.Lock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
	c.mu.Unlock()

	c.removeResolverFiles(func(domain string) bool { return true })
	return nil
}

func (c *darwinConfigurator) SupportsSplitDNS() bool {
	return true
}

func (c *darwinConfigurator) SetDNS(cfg OSConfig) error {
	// Check if we need to start a local DNS listener.
	// On macOS CLI, packets to 100.100.100.100 don't reach the TUN device
	// because mDNSResponder mediates all DNS. We work around this by running
	// a local DNS listener on 127.0.0.1:53.
	needsLocalListener := false
	for _, ip := range cfg.Nameservers {
		if ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() {
			needsLocalListener = true
			break
		}
	}

	c.mu.Lock()
	hasResolver := c.resolver != nil
	c.mu.Unlock()

	// Determine which nameserver to use in /etc/resolver files
	var resolverNameservers []netip.Addr
	var listenerPort int
	if needsLocalListener && hasResolver {
		// Start local DNS listener and use 127.0.0.1 in resolver files
		port, err := c.ensureLocalListener()
		if err != nil {
			c.logf("failed to start local DNS listener: %v; falling back to 100.100.100.100", err)
			resolverNameservers = cfg.Nameservers
		} else {
			// Use 127.0.0.1:<port> instead of 100.100.100.100
			resolverNameservers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
			listenerPort = port
			c.logf("local DNS listener running on 127.0.0.1:%d", port)
		}
	} else {
		resolverNameservers = cfg.Nameservers
		// Stop any existing listener if we don't need it
		c.stopLocalListener()
	}

	var buf bytes.Buffer
	buf.WriteString(macResolverFileHeader)
	for _, ip := range resolverNameservers {
		buf.WriteString("nameserver ")
		buf.WriteString(ip.String())
		buf.WriteString("\n")
	}
	// Add port directive if using local listener on non-standard port
	if listenerPort != 0 {
		fmt.Fprintf(&buf, "port %d\n", listenerPort)
	}

	if err := os.MkdirAll("/etc/resolver", 0755); err != nil {
		return err
	}

	var keep map[string]bool

	// Add a dummy file to /etc/resolver with a "search ..." directive if we have
	// search suffixes to add.
	if len(cfg.SearchDomains) > 0 {
		const searchFile = "search.tailscale" // fake DNS suffix+TLD to put our search
		mak.Set(&keep, searchFile, true)
		var sbuf bytes.Buffer
		sbuf.WriteString(macResolverFileHeader)
		sbuf.WriteString("search")
		for _, d := range cfg.SearchDomains {
			sbuf.WriteString(" ")
			sbuf.WriteString(string(d.WithoutTrailingDot()))
		}
		sbuf.WriteString("\n")
		if err := os.WriteFile("/etc/resolver/"+searchFile, sbuf.Bytes(), 0644); err != nil {
			return err
		}
	}

	for _, d := range cfg.MatchDomains {
		fileBase := string(d.WithoutTrailingDot())
		mak.Set(&keep, fileBase, true)
		fullPath := "/etc/resolver/" + fileBase

		if err := os.WriteFile(fullPath, buf.Bytes(), 0644); err != nil {
			return err
		}
	}
	return c.removeResolverFiles(func(domain string) bool { return !keep[domain] })
}

// tailscaleDNSPort is the preferred port for the local DNS listener.
// We avoid port 53 because macOS intercepts it at a low level.
// This port is registered with IANA for Tailscale DNS (pending registration,
// using 5533 as it visually resembles "53" with padding).
const tailscaleDNSPort = 5533

// ensureLocalListener starts a local DNS listener on 127.0.0.1 if not already running.
// Returns the port the listener is bound to.
func (c *darwinConfigurator) ensureLocalListener() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.listener != nil {
		// Already running
		return c.listenerPort, nil
	}

	if c.resolver == nil {
		return 0, nil // No resolver set, can't handle queries
	}

	// Try the preferred Tailscale DNS port first.
	// If that fails (e.g., another process using it), let the OS assign a port.
	// We avoid port 53 because macOS intercepts it at a low level before
	// it reaches userspace listeners.
	var conn *net.UDPConn
	var err error
	for _, port := range []int{tailscaleDNSPort, 0} {
		addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
		conn, err = net.ListenUDP("udp", addr)
		if err == nil {
			break
		}
		if port == tailscaleDNSPort {
			c.logf("preferred DNS port %d unavailable, using ephemeral port: %v", port, err)
		}
	}
	if err != nil {
		return 0, err
	}

	// Get the actual port (important when OS assigned it)
	actualPort := conn.LocalAddr().(*net.UDPAddr).Port

	c.listener = conn
	c.listenerPort = actualPort
	c.ctx, c.cancel = context.WithCancel(context.Background())

	go c.runLocalListener(c.ctx, conn, c.resolver)
	return actualPort, nil
}

// stopLocalListener stops the local DNS listener if running.
func (c *darwinConfigurator) stopLocalListener() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	if c.listener != nil {
		c.listener.Close()
		c.listener = nil
	}
}

// runLocalListener handles incoming DNS queries on the local listener.
func (c *darwinConfigurator) runLocalListener(ctx context.Context, conn *net.UDPConn, res *resolver.Resolver) {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				c.logf("local DNS listener read error: %v", err)
				continue
			}
		}

		// Handle the query in a goroutine
		query := make([]byte, n)
		copy(query, buf[:n])
		go c.handleLocalQuery(ctx, conn, addr, query, res)
	}
}

// handleLocalQuery processes a single DNS query and sends the response.
func (c *darwinConfigurator) handleLocalQuery(ctx context.Context, conn *net.UDPConn, addr *net.UDPAddr, query []byte, res *resolver.Resolver) {
	from := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(addr.Port))
	resp, err := res.Query(ctx, query, "udp", from)
	if err != nil {
		c.logf("local DNS query error: %v", err)
		return
	}

	_, err = conn.WriteToUDP(resp, addr)
	if err != nil {
		c.logf("local DNS response write error: %v", err)
	}
}

// GetBaseConfig returns the current OS DNS configuration, extracting it from /etc/resolv.conf.
// We should really be using the SystemConfiguration framework to get this information, as this
// is not a stable public API, and is provided mostly as a compatibility effort with Unix
// tools. Apple might break this in the future. But honestly, parsing the output of `scutil --dns`
// is *even more* likely to break in the future.
func (c *darwinConfigurator) GetBaseConfig() (OSConfig, error) {
	cfg := OSConfig{}

	resolvConf, err := resolvconffile.ParseFile("/etc/resolv.conf")
	if err != nil {
		c.logf("failed to parse /etc/resolv.conf: %v", err)
		return cfg, ErrGetBaseConfigNotSupported
	}

	for _, ns := range resolvConf.Nameservers {
		if ns == tsaddr.TailscaleServiceIP() || ns == tsaddr.TailscaleServiceIPv6() {
			// If we find Quad100 in /etc/resolv.conf, we should ignore it
			c.logf("ignoring 100.100.100.100 resolver IP found in /etc/resolv.conf")
			continue
		}
		cfg.Nameservers = append(cfg.Nameservers, ns)
	}
	cfg.SearchDomains = resolvConf.SearchDomains

	if len(cfg.Nameservers) == 0 {
		// Log a warning in case we couldn't find any nameservers in /etc/resolv.conf.
		c.logf("no nameservers found in /etc/resolv.conf, DNS resolution might fail")
	}

	return cfg, nil
}

const macResolverFileHeader = "# Added by tailscaled\n"

// removeResolverFiles deletes all files in /etc/resolver for which the shouldDelete
// func returns true.
func (c *darwinConfigurator) removeResolverFiles(shouldDelete func(domain string) bool) error {
	dents, err := os.ReadDir("/etc/resolver")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, de := range dents {
		if !de.Type().IsRegular() {
			continue
		}
		name := de.Name()
		if !shouldDelete(name) {
			continue
		}
		fullPath := "/etc/resolver/" + name
		contents, err := os.ReadFile(fullPath)
		if err != nil {
			if os.IsNotExist(err) { // race?
				continue
			}
			return err
		}
		if !mem.HasPrefix(mem.B(contents), mem.S(macResolverFileHeader)) {
			continue
		}
		if err := os.Remove(fullPath); err != nil {
			return err
		}
	}
	return nil
}
