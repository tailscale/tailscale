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
	"sync"
	"time"

	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
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
	ipAndGateway func() (gw, ip netaddr.IP, ok bool)
	onChange     func() // or nil

	mu sync.Mutex // guards following, and all fields thereof

	// runningCreate is whether we're currently working on creating
	// a port mapping (whether GetCachedMappingOrStartCreatingOne kicked
	// off a createMapping goroutine).
	runningCreate bool

	lastMyIP netaddr.IP
	lastGW   netaddr.IP
	closed   bool

	lastProbe time.Time

	pmpPubIP     netaddr.IP // non-zero if known
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
	External() netaddr.IPPort
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
	gw         netaddr.IP
	external   netaddr.IPPort
	internal   netaddr.IPPort
	renewAfter time.Time // the time at which we want to renew the mapping
	goodUntil  time.Time // the mapping's total lifetime
	epoch      uint32
}

// externalValid reports whether m.external is valid, with both its IP and Port populated.
func (m *pmpMapping) externalValid() bool {
	return !m.external.IP().IsZero() && m.external.Port() != 0
}

func (p *pmpMapping) GoodUntil() time.Time     { return p.goodUntil }
func (p *pmpMapping) RenewAfter() time.Time    { return p.renewAfter }
func (p *pmpMapping) External() netaddr.IPPort { return p.external }

// Release does a best effort fire-and-forget release of the PMP mapping m.
func (m *pmpMapping) Release(ctx context.Context) {
	uc, err := netns.Listener().ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return
	}
	defer uc.Close()
	pkt := buildPMPRequestMappingPacket(m.internal.Port(), m.external.Port(), pmpMapLifetimeDelete)
	uc.WriteTo(pkt, netaddr.IPPortFrom(m.gw, pmpPort).UDPAddr())
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
func (c *Client) SetGatewayLookupFunc(f func() (gw, myIP netaddr.IP, ok bool)) {
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

func (c *Client) gatewayAndSelfIP() (gw, myIP netaddr.IP, ok bool) {
	gw, myIP, ok = c.ipAndGateway()
	if !ok {
		gw = netaddr.IP{}
		myIP = netaddr.IP{}
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

func (c *Client) invalidateMappingsLocked(releaseOld bool) {
	if c.mapping != nil {
		if releaseOld {
			c.mapping.Release(context.Background())
		}
		c.mapping = nil
	}
	c.pmpPubIP = netaddr.IP{}
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
	return !c.pmpPubIP.IsZero() && c.pmpPubIPTime.After(time.Now().Add(-trustServiceStillAvailableDuration))
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
)

// GetCachedMappingOrStartCreatingOne quickly returns with our current cached portmapping, if any.
// If there's not one, it starts up a background goroutine to create one.
// If the background goroutine ends up creating one, the onChange hook registered with the
// NewClient constructor (if any) will fire.
func (c *Client) GetCachedMappingOrStartCreatingOne() (external netaddr.IPPort, ok bool) {
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
	return netaddr.IPPort{}, false
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
var wildcardIP = netaddr.MustParseIP("0.0.0.0")

// createOrGetMapping either creates a new mapping or returns a cached
// valid one.
//
// If no mapping is available, the error will be of type
// NoMappingError; see IsNoMappingError.
func (c *Client) createOrGetMapping(ctx context.Context) (external netaddr.IPPort, err error) {
	if DisableUPnP && DisablePCP && DisablePMP {
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
	}
	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		return netaddr.IPPort{}, NoMappingError{ErrGatewayRange}
	}

	c.mu.Lock()
	localPort := c.localPort
	internalAddr := netaddr.IPPortFrom(myIP, localPort)

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
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
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
		gw:       gw,
		internal: internalAddr,
	}
	if haveRecentPMP {
		m.external = m.external.WithIP(c.pmpPubIP)
	}
	if c.lastProbe.After(now.Add(-5*time.Second)) && !haveRecentPMP && !haveRecentPCP {
		c.mu.Unlock()
		// fallback to UPnP portmapping
		if external, ok := c.getUPnPPortMapping(ctx, gw, internalAddr, prevPort); ok {
			return external, nil
		}
		return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
	}
	c.mu.Unlock()

	uc, err := netns.Listener().ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		return netaddr.IPPort{}, err
	}
	defer uc.Close()

	uc.SetReadDeadline(time.Now().Add(portMapServiceTimeout))
	defer closeCloserOnContextDone(ctx, uc)()

	pxpAddr := netaddr.IPPortFrom(gw, pmpPort)
	pxpAddru := pxpAddr.UDPAddr()

	preferPCP := !DisablePCP && (DisablePMP || (!haveRecentPMP && haveRecentPCP))

	// Create a mapping, defaulting to PMP unless only PCP was seen recently.
	if preferPCP {
		// TODO replace wildcardIP here with previous external if known.
		// Only do PCP mapping in the case when PMP did not appear to be available recently.
		pkt := buildPCPRequestMappingPacket(myIP, localPort, prevPort, pcpMapLifetimeSec, wildcardIP)
		if _, err := uc.WriteTo(pkt, pxpAddru); err != nil {
			return netaddr.IPPort{}, err
		}
	} else {
		// Ask for our external address if needed.
		if m.external.IP().IsZero() {
			if _, err := uc.WriteTo(pmpReqExternalAddrPacket, pxpAddru); err != nil {
				return netaddr.IPPort{}, err
			}
		}

		pkt := buildPMPRequestMappingPacket(localPort, prevPort, pmpMapLifetimeSec)
		if _, err := uc.WriteTo(pkt, pxpAddru); err != nil {
			return netaddr.IPPort{}, err
		}
	}

	res := make([]byte, 1500)
	for {
		n, srci, err := uc.ReadFrom(res)
		if err != nil {
			if ctx.Err() == context.Canceled {
				return netaddr.IPPort{}, err
			}
			// fallback to UPnP portmapping
			if mapping, ok := c.getUPnPPortMapping(ctx, gw, internalAddr, prevPort); ok {
				return mapping, nil
			}
			return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
		}
		srcu := srci.(*net.UDPAddr)
		src, ok := netaddr.FromStdAddr(srcu.IP, srcu.Port, srcu.Zone)
		if !ok {
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
					return netaddr.IPPort{}, NoMappingError{fmt.Errorf("PMP response Op=0x%x,Res=0x%x", pres.OpCode, pres.ResultCode)}
				}
				if pres.OpCode == pmpOpReply|pmpOpMapPublicAddr {
					m.external = m.external.WithIP(pres.PublicAddr)
				}
				if pres.OpCode == pmpOpReply|pmpOpMapUDP {
					m.external = m.external.WithPort(pres.ExternalPort)
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
					return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
				}
				pcpMapping.internal = m.internal
				pcpMapping.gw = gw
				c.mu.Lock()
				defer c.mu.Unlock()
				c.mapping = pcpMapping
				return pcpMapping.external, nil
			default:
				c.logf("unknown PMP/PCP version number: %d %v", version, res[:n])
				return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
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

type pmpResultCode uint16

// NAT-PMP constants.
const (
	pmpPort              = 5351
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
	PublicAddr netaddr.IP
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

	uc, err := netns.Listener().ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		c.logf("ProbePCP: %v", err)
		return res, err
	}
	defer uc.Close()
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	defer closeCloserOnContextDone(ctx, uc)()

	pcpAddr := netaddr.IPPortFrom(gw, pcpPort).UDPAddr()
	pmpAddr := netaddr.IPPortFrom(gw, pmpPort).UDPAddr()
	upnpAddr := netaddr.IPPortFrom(gw, upnpPort).UDPAddr()

	// Don't send probes to services that we recently learned (for
	// the same gw/myIP) are available. See
	// https://github.com/tailscale/tailscale/issues/1001
	if c.sawPMPRecently() {
		res.PMP = true
	} else if !DisablePMP {
		uc.WriteTo(pmpReqExternalAddrPacket, pmpAddr)
	}
	if c.sawPCPRecently() {
		res.PCP = true
	} else if !DisablePCP {
		uc.WriteTo(pcpAnnounceRequest(myIP), pcpAddr)
	}
	if c.sawUPnPRecently() {
		res.UPnP = true
	} else if !DisableUPnP {
		uc.WriteTo(uPnPPacket, upnpAddr)
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
		port := addr.(*net.UDPAddr).Port
		switch port {
		case upnpPort:
			if mem.Contains(mem.B(buf[:n]), mem.S(":InternetGatewayDevice:")) {
				meta, err := parseUPnPDiscoResponse(buf[:n])
				if err != nil {
					c.logf("unrecognized UPnP discovery response; ignoring")
				}
				if VerboseLogs {
					c.logf("UPnP reply %+v, %q", meta, buf[:n])
				}
				res.UPnP = true
				c.mu.Lock()
				c.uPnPSawTime = time.Now()
				c.uPnPMeta = meta
				c.mu.Unlock()
			}
		case pcpPort: // same as pmpPort
			if pres, ok := parsePCPResponse(buf[:n]); ok {
				if pres.OpCode == pcpOpReply|pcpOpAnnounce {
					pcpHeard = true
					c.mu.Lock()
					c.pcpSawTime = time.Now()
					c.mu.Unlock()
					switch pres.ResultCode {
					case pcpCodeOK:
						c.logf("Got PCP response: epoch: %v", pres.Epoch)
						res.PCP = true
						continue
					case pcpCodeNotAuthorized:
						// A PCP service is running, but refuses to
						// provide port mapping services.
						res.PCP = false
						continue
					default:
						// Fall through to unexpected log line.
					}
				}
				c.logf("unexpected PCP probe response: %+v", pres)
			}
			if pres, ok := parsePMPResponse(buf[:n]); ok {
				if pres.OpCode == pmpOpReply|pmpOpMapPublicAddr && pres.ResultCode == pmpCodeOK {
					c.logf("Got PMP response; IP: %v, epoch: %v", pres.PublicAddr, pres.SecondsSinceEpoch)
					res.PMP = true
					c.mu.Lock()
					c.pmpPubIP = pres.PublicAddr
					c.pmpPubIPTime = time.Now()
					c.pmpLastEpoch = pres.SecondsSinceEpoch
					c.mu.Unlock()
					continue
				}
				c.logf("unexpected PMP probe response: %+v", pres)
			}
		}
	}
}

var pmpReqExternalAddrPacket = []byte{pmpVersion, pmpOpMapPublicAddr} // 0, 0

const (
	upnpPort = 1900 // for UDP discovery only; TCP port discovered later
)

// uPnPPacket is the UPnP UDP discovery packet's request body.
var uPnPPacket = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: ssdp:all\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n")
