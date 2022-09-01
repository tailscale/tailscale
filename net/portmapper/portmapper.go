// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package portmapper is a UDP port mapping client. It currently allows for mapping over
// NAT-PMP, UPnP, and PCP.
package portmapper

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/neterror"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
)

// Debug knobs for "tailscaled debug --portmap".
var (
	VerboseLogs bool

	// Disable* disables a specific service from mapping.

	DisableUPnP bool
	DisablePMP  bool
	DisablePCP  bool
)

// References:
//
// NAT-PMP: https://tools.ietf.org/html/rfc6886

// portMapServiceTimeout is the time we wait for port mapping
// services (UPnP, NAT-PMP, PCP) to respond before we give up and
// decide that they're not there. Since these services are on the
// same LAN as this machine and a single L3 hop away, we don't
// give them much time to respond.
const portMapServiceTimeout = 250 * time.Millisecond

// trustServiceStillAvailableDuration is how often we re-verify a port
// mapping service is available.
const trustServiceStillAvailableDuration = 10 * time.Minute

// Client is a port mapping client.
type Client struct {
	logf         logger.Logf
	ipAndGateway func() (gw, ip netip.Addr, ok bool)
	onChange     func() // or nil
	testPxPPort  uint16 // if non-zero, pxpPort to use for tests
	testUPnPPort uint16 // if non-zero, uPnPPort to use for tests

	mu sync.Mutex // guards following, and all fields thereof

	// runningCreate is whether we're currently working on creating
	// a port mapping (whether GetCachedMappingOrStartCreatingOne kicked
	// off a createMapping goroutine).
	runningCreate bool

	lastMyIP netip.Addr
	lastGW   netip.Addr
	closed   bool

	lastProbe time.Time

	pmpPubIP     netip.Addr // non-zero if known
	pmpPubIPTime time.Time  // time pmpPubIP last verified
	pmpLastEpoch uint32

	pcpSawTime time.Time // time we last saw PCP was available

	uPnPSawTime    time.Time         // time we last saw UPnP was available
	uPnPMeta       uPnPDiscoResponse // Location header from UPnP UDP discovery response
	uPnPHTTPClient *http.Client      // netns-configured HTTP client for UPnP; nil until needed

	localPort uint16

	mapping mapping // non-nil if we have a mapping
}

// mapping represents a created port-mapping over some protocol.  It specifies a lease duration,
// how to release the mapping, and whether the map is still valid.
//
// After a mapping is created, it should be immutable, and thus reads should be safe across
// concurrent goroutines.
type mapping interface {
	// Release will attempt to unmap the established port mapping. It will block until completion,
	// but can be called asynchronously. Release should be idempotent, and thus even if called
	// multiple times should not cause additional side-effects.
	Release(context.Context)
	// goodUntil will return the lease time that the mapping is valid for.
	GoodUntil() time.Time
	// renewAfter returns the earliest time that the mapping should be renewed.
	RenewAfter() time.Time
	// externalIPPort indicates what port the mapping can be reached from on the outside.
	External() netip.AddrPort
}

// HaveMapping reports whether we have a current valid mapping.
func (c *Client) HaveMapping() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mapping != nil && c.mapping.GoodUntil().After(time.Now())
}

// pmpMapping is an already-created PMP mapping.
//
// All fields are immutable once created.
type pmpMapping struct {
	c          *Client
	gw         netip.AddrPort
	external   netip.AddrPort
	internal   netip.AddrPort
	renewAfter time.Time // the time at which we want to renew the mapping
	goodUntil  time.Time // the mapping's total lifetime
	epoch      uint32
}

// externalValid reports whether m.external is valid, with both its IP and Port populated.
func (m *pmpMapping) externalValid() bool {
	return m.external.Addr().IsValid() && m.external.Port() != 0
}

func (p *pmpMapping) GoodUntil() time.Time     { return p.goodUntil }
func (p *pmpMapping) RenewAfter() time.Time    { return p.renewAfter }
func (p *pmpMapping) External() netip.AddrPort { return p.external }

// Release does a best effort fire-and-forget release of the PMP mapping m.
func (m *pmpMapping) Release(ctx context.Context) {
	uc, err := m.c.listenPacket(ctx, "udp4", ":0")
	if err != nil {
		return
	}
	defer uc.Close()
	pkt := buildPMPRequestMappingPacket(m.internal.Port(), m.external.Port(), pmpMapLifetimeDelete)
	uc.WriteToUDPAddrPort(pkt, m.gw)
}

// NewClient returns a new portmapping client.
//
// The optional onChange argument specifies a func to run in a new
// goroutine whenever the port mapping status has changed. If nil,
// it doesn't make a callback.
func NewClient(logf logger.Logf, onChange func()) *Client {
	return &Client{
		logf:         logf,
		ipAndGateway: interfaces.LikelyHomeRouterIP,
		onChange:     onChange,
	}
}

// SetGatewayLookupFunc set the func that returns the machine's default gateway IP, and
// the primary IP address for that gateway. It must be called before the client is used.
// If not called, interfaces.LikelyHomeRouterIP is used.
func (c *Client) SetGatewayLookupFunc(f func() (gw, myIP netip.Addr, ok bool)) {
	c.ipAndGateway = f
}

// NoteNetworkDown should be called when the network has transitioned to a down state.
// It's too late to release port mappings at this point (the user might've just turned off
// their wifi), but we can make sure we invalidate mappings for later when the network
// comes back.
func (c *Client) NoteNetworkDown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidateMappingsLocked(false)
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.invalidateMappingsLocked(true)
	// TODO: close some future ever-listening UDP socket(s),
	// waiting for multicast announcements from router.
	return nil
}

// SetLocalPort updates the local port number to which we want to port
// map UDP traffic.
func (c *Client) SetLocalPort(localPort uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.localPort == localPort {
		return
	}
	c.localPort = localPort
	c.invalidateMappingsLocked(true)
}

func (c *Client) gatewayAndSelfIP() (gw, myIP netip.Addr, ok bool) {
	gw, myIP, ok = c.ipAndGateway()
	if !ok {
		gw = netip.Addr{}
		myIP = netip.Addr{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if gw != c.lastGW || myIP != c.lastMyIP || !ok {
		c.lastMyIP = myIP
		c.lastGW = gw
		c.invalidateMappingsLocked(true)
	}
	return
}

// pxpPort returns the NAT-PMP and PCP port number.
// It returns 5351, except for in tests where it varies by run.
func (c *Client) pxpPort() uint16 {
	if c.testPxPPort != 0 {
		return c.testPxPPort
	}
	return pmpDefaultPort
}

// upnpPort returns the UPnP discovery port number.
// It returns 1900, except for in tests where it varies by run.
func (c *Client) upnpPort() uint16 {
	if c.testUPnPPort != 0 {
		return c.testUPnPPort
	}
	return upnpDefaultPort
}

func (c *Client) listenPacket(ctx context.Context, network, addr string) (nettype.PacketConn, error) {
	// When running under testing conditions, we bind the IGD server
	// to localhost, and may be running in an environment where our
	// netns code would decide that binding the portmapper client
	// socket to the default route interface is the correct way to
	// ensure connectivity. This can result in us trying to send
	// packets for 127.0.0.1 out the machine's LAN interface, which
	// obviously gets dropped on the floor.
	//
	// So, under those testing conditions, do _not_ use netns to
	// create listening sockets. Such sockets are vulnerable to
	// routing loops, but it's tests that don't set up routing loops,
	// so we don't care.
	if c.testPxPPort != 0 || c.testUPnPPort != 0 {
		var lc net.ListenConfig
		pc, err := lc.ListenPacket(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return pc.(*net.UDPConn), nil
	}
	pc, err := netns.Listener(c.logf).ListenPacket(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

func (c *Client) invalidateMappingsLocked(releaseOld bool) {
	if c.mapping != nil {
		if releaseOld {
			c.mapping.Release(context.Background())
		}
		c.mapping = nil
	}
	c.pmpPubIP = netip.Addr{}
	c.pmpPubIPTime = time.Time{}
	c.pcpSawTime = time.Time{}
	c.uPnPSawTime = time.Time{}
	c.uPnPMeta = uPnPDiscoResponse{}
}

func (c *Client) sawPMPRecently() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sawPMPRecentlyLocked()
}

func (c *Client) sawPMPRecentlyLocked() bool {
	return c.pmpPubIP.IsValid() && c.pmpPubIPTime.After(time.Now().Add(-trustServiceStillAvailableDuration))
}

func (c *Client) sawPCPRecently() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sawPCPRecentlyLocked()
}

func (c *Client) sawPCPRecentlyLocked() bool {
	return c.pcpSawTime.After(time.Now().Add(-trustServiceStillAvailableDuration))
}

func (c *Client) sawUPnPRecently() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.uPnPSawTime.After(time.Now().Add(-trustServiceStillAvailableDuration))
}

// closeCloserOnContextDone starts a new goroutine to call c.Close
// if/when ctx becomes done.
// To stop the goroutine, call the returned stop func.
func closeCloserOnContextDone(ctx context.Context, c io.Closer) (stop func()) {
	// Close uc on ctx being done.
	ctxDone := ctx.Done()
	if ctxDone == nil {
		return func() {}
	}
	stopWaitDone := make(chan struct{})
	go func() {
		select {
		case <-stopWaitDone:
		case <-ctxDone:
			c.Close()
		}
	}()
	return func() { close(stopWaitDone) }
}

// NoMappingError is returned when no NAT mapping could be done.
type NoMappingError struct {
	err error
}

func (nme NoMappingError) Unwrap() error { return nme.err }
func (nme NoMappingError) Error() string { return fmt.Sprintf("no NAT mapping available: %v", nme.err) }

// IsNoMappingError reports whether err is of type NoMappingError.
func IsNoMappingError(err error) bool {
	_, ok := err.(NoMappingError)
	return ok
}

var (
	ErrNoPortMappingServices = errors.New("no port mapping services were found")
	ErrGatewayRange          = errors.New("skipping portmap; gateway range likely lacks support")
	ErrGatewayIPv6           = errors.New("skipping portmap; no IPv6 support for portmapping")
)

// GetCachedMappingOrStartCreatingOne quickly returns with our current cached portmapping, if any.
// If there's not one, it starts up a background goroutine to create one.
// If the background goroutine ends up creating one, the onChange hook registered with the
// NewClient constructor (if any) will fire.
func (c *Client) GetCachedMappingOrStartCreatingOne() (external netip.AddrPort, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Do we have an existing mapping that's valid?
	now := time.Now()
	if m := c.mapping; m != nil {
		if now.Before(m.GoodUntil()) {
			if now.After(m.RenewAfter()) {
				c.maybeStartMappingLocked()
			}
			return m.External(), true
		}
	}

	c.maybeStartMappingLocked()
	return netip.AddrPort{}, false
}

// maybeStartMappingLocked starts a createMapping goroutine up, if one isn't already running.
//
// c.mu must be held.
func (c *Client) maybeStartMappingLocked() {
	if !c.runningCreate {
		c.runningCreate = true
		go c.createMapping()
	}
}

func (c *Client) createMapping() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.runningCreate = false
	}()

	if _, err := c.createOrGetMapping(ctx); err == nil && c.onChange != nil {
		go c.onChange()
	} else if err != nil && !IsNoMappingError(err) {
		c.logf("createOrGetMapping: %v", err)
	}
}

// wildcardIP is used when the previous external IP is not known for PCP port mapping.
var wildcardIP = netip.MustParseAddr("0.0.0.0")

// createOrGetMapping either creates a new mapping or returns a cached
// valid one.
//
// If no mapping is available, the error will be of type
// NoMappingError; see IsNoMappingError.
func (c *Client) createOrGetMapping(ctx context.Context) (external netip.AddrPort, err error) {
	if DisableUPnP && DisablePCP && DisablePMP {
		return netip.AddrPort{}, NoMappingError{ErrNoPortMappingServices}
	}
	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		return netip.AddrPort{}, NoMappingError{ErrGatewayRange}
	}
	if gw.Is6() {
		return netip.AddrPort{}, NoMappingError{ErrGatewayIPv6}
	}

	c.mu.Lock()
	localPort := c.localPort
	internalAddr := netip.AddrPortFrom(myIP, localPort)

	// prevPort is the port we had most previously, if any. We try
	// to ask for the same port. 0 means to give us any port.
	var prevPort uint16

	// Do we have an existing mapping that's valid?
	now := time.Now()
	if m := c.mapping; m != nil {
		if now.Before(m.RenewAfter()) {
			defer c.mu.Unlock()
			return m.External(), nil
		}
		// The mapping might still be valid, so just try to renew it.
		prevPort = m.External().Port()
	}

	if DisablePCP && DisablePMP {
		c.mu.Unlock()
		if external, ok := c.getUPnPPortMapping(ctx, gw, internalAddr, prevPort); ok {
			return external, nil
		}
		return netip.AddrPort{}, NoMappingError{ErrNoPortMappingServices}
	}

	// If we just did a Probe (e.g. via netchecker) but didn't
	// find a PMP service, bail out early rather than probing
	// again. Cuts down latency for most clients.
	haveRecentPMP := c.sawPMPRecentlyLocked()
	haveRecentPCP := c.sawPCPRecentlyLocked()

	// Since PMP mapping may require multiple calls, and it's not clear from the outset
	// whether we're doing a PCP or PMP call, initialize the PMP mapping here,
	// and only return it once completed.
	//
	// PCP returns all the information necessary for a mapping in a single packet, so we can
	// construct it upon receiving that packet.
	m := &pmpMapping{
		c:        c,
		gw:       netip.AddrPortFrom(gw, c.pxpPort()),
		internal: internalAddr,
	}
	if haveRecentPMP {
		m.external = netip.AddrPortFrom(c.pmpPubIP, m.external.Port())
	}
	if c.lastProbe.After(now.Add(-5*time.Second)) && !haveRecentPMP && !haveRecentPCP {
		c.mu.Unlock()
		// fallback to UPnP portmapping
		if external, ok := c.getUPnPPortMapping(ctx, gw, internalAddr, prevPort); ok {
			return external, nil
		}
		return netip.AddrPort{}, NoMappingError{ErrNoPortMappingServices}
	}
	c.mu.Unlock()

	uc, err := c.listenPacket(ctx, "udp4", ":0")
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer uc.Close()

	uc.SetReadDeadline(time.Now().Add(portMapServiceTimeout))
	defer closeCloserOnContextDone(ctx, uc)()

	pxpAddr := netip.AddrPortFrom(gw, c.pxpPort())

	preferPCP := !DisablePCP && (DisablePMP || (!haveRecentPMP && haveRecentPCP))

	// Create a mapping, defaulting to PMP unless only PCP was seen recently.
	if preferPCP {
		// TODO replace wildcardIP here with previous external if known.
		// Only do PCP mapping in the case when PMP did not appear to be available recently.
		pkt := buildPCPRequestMappingPacket(myIP, localPort, prevPort, pcpMapLifetimeSec, wildcardIP)
		if _, err := uc.WriteToUDPAddrPort(pkt, pxpAddr); err != nil {
			if neterror.TreatAsLostUDP(err) {
				err = NoMappingError{ErrNoPortMappingServices}
			}
			return netip.AddrPort{}, err
		}
	} else {
		// Ask for our external address if needed.
		if !m.external.Addr().IsValid() {
			if _, err := uc.WriteToUDPAddrPort(pmpReqExternalAddrPacket, pxpAddr); err != nil {
				if neterror.TreatAsLostUDP(err) {
					err = NoMappingError{ErrNoPortMappingServices}
				}
				return netip.AddrPort{}, err
			}
		}

		pkt := buildPMPRequestMappingPacket(localPort, prevPort, pmpMapLifetimeSec)
		if _, err := uc.WriteToUDPAddrPort(pkt, pxpAddr); err != nil {
			if neterror.TreatAsLostUDP(err) {
				err = NoMappingError{ErrNoPortMappingServices}
			}
			return netip.AddrPort{}, err
		}
	}

	res := make([]byte, 1500)
	for {
		n, srci, err := uc.ReadFrom(res)
		if err != nil {
			if ctx.Err() == context.Canceled {
				return netip.AddrPort{}, err
			}
			// fallback to UPnP portmapping
			if mapping, ok := c.getUPnPPortMapping(ctx, gw, internalAddr, prevPort); ok {
				return mapping, nil
			}
			return netip.AddrPort{}, NoMappingError{ErrNoPortMappingServices}
		}
		srcu := srci.(*net.UDPAddr)
		src := netaddr.Unmap(srcu.AddrPort())
		if !src.IsValid() {
			continue
		}
		if src == pxpAddr {
			version := res[0]
			switch version {
			case pmpVersion:
				pres, ok := parsePMPResponse(res[:n])
				if !ok {
					c.logf("unexpected PMP response: % 02x", res[:n])
					continue
				}
				if pres.ResultCode != 0 {
					return netip.AddrPort{}, NoMappingError{fmt.Errorf("PMP response Op=0x%x,Res=0x%x", pres.OpCode, pres.ResultCode)}
				}
				if pres.OpCode == pmpOpReply|pmpOpMapPublicAddr {
					m.external = netip.AddrPortFrom(pres.PublicAddr, m.external.Port())
				}
				if pres.OpCode == pmpOpReply|pmpOpMapUDP {
					m.external = netip.AddrPortFrom(m.external.Addr(), pres.ExternalPort)
					d := time.Duration(pres.MappingValidSeconds) * time.Second
					now := time.Now()
					m.goodUntil = now.Add(d)
					m.renewAfter = now.Add(d / 2) // renew in half the time
					m.epoch = pres.SecondsSinceEpoch
				}
			case pcpVersion:
				pcpMapping, err := parsePCPMapResponse(res[:n])
				if err != nil {
					c.logf("failed to get PCP mapping: %v", err)
					// PCP should only have a single packet response
					return netip.AddrPort{}, NoMappingError{ErrNoPortMappingServices}
				}
				pcpMapping.c = c
				pcpMapping.internal = m.internal
				pcpMapping.gw = netip.AddrPortFrom(gw, c.pxpPort())
				c.mu.Lock()
				defer c.mu.Unlock()
				c.mapping = pcpMapping
				return pcpMapping.external, nil
			default:
				c.logf("unknown PMP/PCP version number: %d %v", version, res[:n])
				return netip.AddrPort{}, NoMappingError{ErrNoPortMappingServices}
			}
		}

		if m.externalValid() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.mapping = m
			return m.external, nil
		}
	}
}

//go:generate go run tailscale.com/cmd/addlicense -year 2021 -file pmpresultcode_string.go go run golang.org/x/tools/cmd/stringer -type=pmpResultCode -trimprefix=pmpCode

type pmpResultCode uint16

// NAT-PMP constants.
const (
	pmpDefaultPort       = 5351
	pmpMapLifetimeSec    = 7200 // RFC recommended 2 hour map duration
	pmpMapLifetimeDelete = 0    // 0 second lifetime deletes

	pmpVersion         = 0
	pmpOpMapPublicAddr = 0
	pmpOpMapUDP        = 1
	pmpOpReply         = 0x80 // OR'd into request's op code on response

	pmpCodeOK                 pmpResultCode = 0
	pmpCodeUnsupportedVersion pmpResultCode = 1
	pmpCodeNotAuthorized      pmpResultCode = 2 // "e.g., box supports mapping, but user has turned feature off"
	pmpCodeNetworkFailure     pmpResultCode = 3 // "e.g., NAT box itself has not obtained a DHCP lease"
	pmpCodeOutOfResources     pmpResultCode = 4
	pmpCodeUnsupportedOpcode  pmpResultCode = 5
)

func buildPMPRequestMappingPacket(localPort, prevPort uint16, lifetimeSec uint32) (pkt []byte) {
	pkt = make([]byte, 12)

	pkt[1] = pmpOpMapUDP
	binary.BigEndian.PutUint16(pkt[4:], localPort)
	binary.BigEndian.PutUint16(pkt[6:], prevPort)
	binary.BigEndian.PutUint32(pkt[8:], lifetimeSec)

	return pkt
}

type pmpResponse struct {
	OpCode            uint8
	ResultCode        pmpResultCode
	SecondsSinceEpoch uint32

	// For Map ops:
	MappingValidSeconds uint32
	InternalPort        uint16
	ExternalPort        uint16

	// For public addr ops:
	PublicAddr netip.Addr
}

func parsePMPResponse(pkt []byte) (res pmpResponse, ok bool) {
	if len(pkt) < 12 {
		return
	}
	ver := pkt[0]
	if ver != 0 {
		return
	}
	res.OpCode = pkt[1]
	res.ResultCode = pmpResultCode(binary.BigEndian.Uint16(pkt[2:]))
	res.SecondsSinceEpoch = binary.BigEndian.Uint32(pkt[4:])

	if res.OpCode == pmpOpReply|pmpOpMapUDP {
		if len(pkt) != 16 {
			return res, false
		}
		res.InternalPort = binary.BigEndian.Uint16(pkt[8:])
		res.ExternalPort = binary.BigEndian.Uint16(pkt[10:])
		res.MappingValidSeconds = binary.BigEndian.Uint32(pkt[12:])
	}

	if res.OpCode == pmpOpReply|pmpOpMapPublicAddr {
		if len(pkt) != 12 {
			return res, false
		}
		res.PublicAddr = netaddr.IPv4(pkt[8], pkt[9], pkt[10], pkt[11])
	}

	return res, true
}

type ProbeResult struct {
	PCP  bool
	PMP  bool
	UPnP bool
}

// Probe returns a summary of which port mapping services are
// available on the network.
//
// If a probe has run recently and there haven't been any network changes since,
// the returned result might be server from the Client's cache, without
// sending any network traffic.
func (c *Client) Probe(ctx context.Context) (res ProbeResult, err error) {
	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		return res, ErrGatewayRange
	}
	defer func() {
		if err == nil {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.lastProbe = time.Now()
		}
	}()

	uc, err := c.listenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		c.logf("ProbePCP: %v", err)
		return res, err
	}
	defer uc.Close()
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	defer closeCloserOnContextDone(ctx, uc)()

	pxpAddr := netip.AddrPortFrom(gw, c.pxpPort())
	upnpAddr := netip.AddrPortFrom(gw, c.upnpPort())
	upnpMulticastAddr := netip.AddrPortFrom(netaddr.IPv4(239, 255, 255, 250), c.upnpPort())

	// Don't send probes to services that we recently learned (for
	// the same gw/myIP) are available. See
	// https://github.com/tailscale/tailscale/issues/1001
	if c.sawPMPRecently() {
		res.PMP = true
	} else if !DisablePMP {
		metricPMPSent.Add(1)
		uc.WriteToUDPAddrPort(pmpReqExternalAddrPacket, pxpAddr)
	}
	if c.sawPCPRecently() {
		res.PCP = true
	} else if !DisablePCP {
		metricPCPSent.Add(1)
		uc.WriteToUDPAddrPort(pcpAnnounceRequest(myIP), pxpAddr)
	}
	if c.sawUPnPRecently() {
		res.UPnP = true
	} else if !DisableUPnP {
		// Strictly speaking, you discover UPnP services by sending an
		// SSDP query (which uPnPPacket is) to udp/1900 on the SSDP
		// multicast address, and then get a flood of responses back
		// from everything on your network.
		//
		// Empirically, many home routers also respond to SSDP queries
		// directed at udp/1900 on their LAN unicast IP
		// (e.g. 192.168.1.1). This is handy because it means we can
		// probe the router directly and likely get a reply. However,
		// the specs do not _require_ UPnP devices to respond to
		// unicast SSDP queries, so some conformant UPnP
		// implementations only respond to multicast queries.
		//
		// In theory, we could send just the multicast query and get
		// all compliant devices to respond. However, we instead send
		// to both a unicast and a multicast addresses, for a couple
		// of reasons:
		//
		// First, some LANs and OSes have broken multicast in one way
		// or another, so it's possible for the multicast query to be
		// lost while the unicast query gets through. But we still
		// have to send the multicast query to also get a response
		// from strict-UPnP devices on multicast-working networks.
		//
		// Second, SSDP's packet dynamics are a bit weird: you send
		// the SSDP query from your unicast IP to the SSDP multicast
		// IP, but responses are from the UPnP devices's _unicast_ IP
		// to your unicast IP. This can confuse some less-intelligent
		// stateful host firewalls, who might block the responses. To
		// work around this, we send the unicast query first, to teach
		// the firewall to expect a unicast response from the router,
		// and then send our multicast query. That way, even if the
		// device doesn't respond to the unicast query, we've set the
		// stage for the host firewall to accept the response to the
		// multicast query.
		//
		// See https://github.com/tailscale/tailscale/issues/3197 for
		// an example of a device that strictly implements UPnP, and
		// only responds to multicast queries.
		//
		// Then we send a discovery packet looking for
		// urn:schemas-upnp-org:device:InternetGatewayDevice:1 specifically, not
		// just ssdp:all, because there appear to be devices which only send
		// their first descriptor (like urn:schemas-wifialliance-org:device:WFADevice:1)
		// in response to ssdp:all. https://github.com/tailscale/tailscale/issues/3557
		metricUPnPSent.Add(1)
		uc.WriteToUDPAddrPort(uPnPPacket, upnpAddr)
		uc.WriteToUDPAddrPort(uPnPPacket, upnpMulticastAddr)
		uc.WriteToUDPAddrPort(uPnPIGDPacket, upnpMulticastAddr)
	}

	buf := make([]byte, 1500)
	pcpHeard := false // true when we get any PCP response
	for {
		if pcpHeard && res.PMP && res.UPnP {
			// Nothing more to discover.
			return res, nil
		}
		n, addr, err := uc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				err = nil
			}
			return res, err
		}
		ip, ok := netip.AddrFromSlice(addr.(*net.UDPAddr).IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		port := uint16(addr.(*net.UDPAddr).Port)
		switch port {
		case c.upnpPort():
			metricUPnPResponse.Add(1)
			if ip == gw && mem.Contains(mem.B(buf[:n]), mem.S(":InternetGatewayDevice:")) {
				meta, err := parseUPnPDiscoResponse(buf[:n])
				if err != nil {
					metricUPnPParseErr.Add(1)
					c.logf("unrecognized UPnP discovery response; ignoring: %v", err)
					continue
				}
				metricUPnPOK.Add(1)
				c.logf("[v1] UPnP reply %+v, %q", meta, buf[:n])
				res.UPnP = true
				c.mu.Lock()
				c.uPnPSawTime = time.Now()
				if c.uPnPMeta != meta {
					c.logf("UPnP meta changed: %+v", meta)
					c.uPnPMeta = meta
					metricUPnPUpdatedMeta.Add(1)
				}
				c.mu.Unlock()
			}
		case c.pxpPort(): // same value for PMP and PCP
			metricPXPResponse.Add(1)
			if pres, ok := parsePCPResponse(buf[:n]); ok {
				if pres.OpCode == pcpOpReply|pcpOpAnnounce {
					pcpHeard = true
					c.mu.Lock()
					c.pcpSawTime = time.Now()
					c.mu.Unlock()
					switch pres.ResultCode {
					case pcpCodeOK:
						c.logf("[v1] Got PCP response: epoch: %v", pres.Epoch)
						res.PCP = true
						metricPCPOK.Add(1)
						continue
					case pcpCodeNotAuthorized:
						// A PCP service is running, but refuses to
						// provide port mapping services.
						res.PCP = false
						metricPCPNotAuthorized.Add(1)
						continue
					case pcpCodeAddressMismatch:
						// A PCP service is running, but it is behind a NAT, so it can't help us.
						res.PCP = false
						metricPCPAddressMismatch.Add(1)
						continue
					default:
						// Fall through to unexpected log line.
					}
				}
				metricPCPUnhandledResponseCode.Add(1)
				c.logf("unexpected PCP probe response: %+v", pres)
			}
			if pres, ok := parsePMPResponse(buf[:n]); ok {
				if pres.OpCode != pmpOpReply|pmpOpMapPublicAddr {
					c.logf("unexpected PMP probe response opcode: %+v", pres)
					metricPMPUnhandledOpcode.Add(1)
					continue
				}
				switch pres.ResultCode {
				case pmpCodeOK:
					metricPMPOK.Add(1)
					c.logf("[v1] Got PMP response; IP: %v, epoch: %v", pres.PublicAddr, pres.SecondsSinceEpoch)
					res.PMP = true
					c.mu.Lock()
					c.pmpPubIP = pres.PublicAddr
					c.pmpPubIPTime = time.Now()
					c.pmpLastEpoch = pres.SecondsSinceEpoch
					c.mu.Unlock()
					continue
				case pmpCodeNotAuthorized:
					metricPMPNotAuthorized.Add(1)
					c.logf("PMP probe failed due result code: %+v", pres)
					continue
				case pmpCodeNetworkFailure:
					metricPMPNetworkFailure.Add(1)
					c.logf("PMP probe failed due result code: %+v", pres)
					continue
				case pmpCodeOutOfResources:
					metricPMPOutOfResources.Add(1)
					c.logf("PMP probe failed due result code: %+v", pres)
					continue
				}
				metricPMPUnhandledResponseCode.Add(1)
				c.logf("unexpected PMP probe response: %+v", pres)
			}
		}
	}
}

var pmpReqExternalAddrPacket = []byte{pmpVersion, pmpOpMapPublicAddr} // 0, 0

const (
	upnpDefaultPort = 1900 // for UDP discovery only; TCP port discovered later
)

// uPnPPacket is the UPnP UDP discovery packet's request body.
var uPnPPacket = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: ssdp:all\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n")

// Send a discovery frame for InternetGatewayDevice, since some devices respond
// to ssdp:all with only their first descriptor (which is often not IGD).
// https://github.com/tailscale/tailscale/issues/3557
var uPnPIGDPacket = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n")

// PCP/PMP metrics
var (
	// metricPXPResponse counts the number of times we received a PMP/PCP response.
	metricPXPResponse = clientmetric.NewCounter("portmap_pxp_response")

	// metricPCPSent counts the number of times we sent a PCP request.
	metricPCPSent = clientmetric.NewCounter("portmap_pcp_sent")

	// metricPCPOK counts the number of times
	// we received a successful PCP response.
	metricPCPOK = clientmetric.NewCounter("portmap_pcp_ok")

	// metricPCPAddressMismatch counts the number of times
	// we received a PCP address mismatch result code.
	metricPCPAddressMismatch = clientmetric.NewCounter("portmap_pcp_address_mismatch")

	// metricPCPNotAuthorized counts the number of times
	// we received a PCP not authorized result code.
	metricPCPNotAuthorized = clientmetric.NewCounter("portmap_pcp_not_authorized")

	// metricPCPUnhandledResponseCode counts the number of times
	// we received an (as yet) unhandled PCP result code.
	metricPCPUnhandledResponseCode = clientmetric.NewCounter("portmap_pcp_unhandled_response_code")

	// metricPMPSent counts the number of times we sent a PMP request.
	metricPMPSent = clientmetric.NewCounter("portmap_pmp_sent")

	// metricPMPOK counts the number of times
	// we received a succesful PMP response.
	metricPMPOK = clientmetric.NewCounter("portmap_pmp_ok")

	// metricPMPUnhandledOpcode counts the number of times
	// we received an unhandled PMP opcode.
	metricPMPUnhandledOpcode = clientmetric.NewCounter("portmap_pmp_unhandled_opcode")

	// metricPMPUnhandledResponseCode counts the number of times
	// we received an unhandled PMP result code.
	metricPMPUnhandledResponseCode = clientmetric.NewCounter("portmap_pmp_unhandled_response_code")

	// metricPMPOutOfResources counts the number of times
	// we received a PCP out of resources result code.
	metricPMPOutOfResources = clientmetric.NewCounter("portmap_pmp_out_of_resources")

	// metricPMPNetworkFailure counts the number of times
	// we received a PCP network failure result code.
	metricPMPNetworkFailure = clientmetric.NewCounter("portmap_pmp_network_failure")

	// metricPMPNotAuthorized counts the number of times
	// we received a PCP not authorized result code.
	metricPMPNotAuthorized = clientmetric.NewCounter("portmap_pmp_not_authorized")
)

// UPnP metrics
var (
	// metricUPnPSent counts the number of times we sent a UPnP request.
	metricUPnPSent = clientmetric.NewCounter("portmap_upnp_sent")

	// metricUPnPResponse counts the number of times we received a UPnP response.
	metricUPnPResponse = clientmetric.NewCounter("portmap_upnp_response")

	// metricUPnPParseErr counts the number of times we failed to parse a UPnP response.
	metricUPnPParseErr = clientmetric.NewCounter("portmap_upnp_parse_err")

	// metricUPnPOK counts the number of times we received a usable UPnP response.
	metricUPnPOK = clientmetric.NewCounter("portmap_upnp_ok")

	// metricUPnPUpdatedMeta counts the number of times
	// we received a UPnP response with a new meta.
	metricUPnPUpdatedMeta = clientmetric.NewCounter("portmap_upnp_updated_meta")
)
