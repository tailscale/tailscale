// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package portmapper is a UDP port mapping client. It currently only does
// NAT-PMP, but will likely do UPnP and perhaps PCP later.
package portmapper

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
)

// References:
//
// NAT-PMP: https://tools.ietf.org/html/rfc6886
// PCP: https://tools.ietf.org/html/rfc6887

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

	mu sync.Mutex // guards following, and all fields thereof

	lastMyIP netaddr.IP
	lastGW   netaddr.IP
	closed   bool

	lastProbe time.Time

	pmpPubIP     netaddr.IP // non-zero if known
	pmpPubIPTime time.Time  // time pmpPubIP last verified
	pmpLastEpoch uint32

	pcpSawTime  time.Time // time we last saw PCP was available
	uPnPSawTime time.Time // time we last saw UPnP was available

	localPort  uint16
	pmpMapping *pmpMapping // non-nil if we have a PMP mapping
}

// HaveMapping reports whether we have a current valid mapping.
func (c *Client) HaveMapping() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pmpMapping != nil && c.pmpMapping.useUntil.After(time.Now())
}

// pmpMapping is an already-created PMP mapping.
//
// All fields are immutable once created.
type pmpMapping struct {
	gw       netaddr.IP
	external netaddr.IPPort
	internal netaddr.IPPort
	useUntil time.Time // the mapping's lifetime minus renewal interval
	epoch    uint32
}

// externalValid reports whether m.external is valid, with both its IP and Port populated.
func (m *pmpMapping) externalValid() bool {
	return !m.external.IP().IsZero() && m.external.Port() != 0
}

// release does a best effort fire-and-forget release of the PMP mapping m.
func (m *pmpMapping) release() {
	uc, err := netns.Listener().ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		return
	}
	defer uc.Close()
	pkt := buildPMPRequestMappingPacket(m.internal.Port(), m.external.Port(), pmpMapLifetimeDelete)
	uc.WriteTo(pkt, netaddr.IPPortFrom(m.gw, pmpPort).UDPAddr())
}

// NewClient returns a new portmapping client.
func NewClient(logf logger.Logf) *Client {
	return &Client{
		logf:         logf,
		ipAndGateway: interfaces.LikelyHomeRouterIP,
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
	if c.pmpMapping != nil {
		if releaseOld {
			c.pmpMapping.release()
		}
		c.pmpMapping = nil
	}
	c.pmpPubIP = netaddr.IP{}
	c.pmpPubIPTime = time.Time{}
	c.pcpSawTime = time.Time{}
	c.uPnPSawTime = time.Time{}
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

// NoMappingError is returned by CreateOrGetMapping when no NAT
// mapping could be returned.
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
	ErrGatewayNotFound       = errors.New("failed to look up gateway address")
)

// CreateOrGetMapping either creates a new mapping or returns a cached
// valid one.
//
// If no mapping is available, the error will be of type
// NoMappingError; see IsNoMappingError.
func (c *Client) CreateOrGetMapping(ctx context.Context) (external netaddr.IPPort, err error) {
	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		return netaddr.IPPort{}, NoMappingError{ErrGatewayNotFound}
	}

	c.mu.Lock()
	localPort := c.localPort
	m := &pmpMapping{
		gw:       gw,
		internal: netaddr.IPPortFrom(myIP, localPort),
	}

	// prevPort is the port we had most previously, if any. We try
	// to ask for the same port. 0 means to give us any port.
	var prevPort uint16

	// Do we have an existing mapping that's valid?
	now := time.Now()
	if m := c.pmpMapping; m != nil {
		if now.Before(m.useUntil) {
			defer c.mu.Unlock()
			return m.external, nil
		}
		// The mapping might still be valid, so just try to renew it.
		prevPort = m.external.Port()
	}

	// If we just did a Probe (e.g. via netchecker) but didn't
	// find a PMP service, bail out early rather than probing
	// again. Cuts down latency for most clients.
	haveRecentPMP := c.sawPMPRecentlyLocked()
	if haveRecentPMP {
		m.external = m.external.WithIP(c.pmpPubIP)
	}
	if c.lastProbe.After(now.Add(-5*time.Second)) && !haveRecentPMP {
		c.mu.Unlock()
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

	pmpAddr := netaddr.IPPortFrom(gw, pmpPort)
	pmpAddru := pmpAddr.UDPAddr()

	// Ask for our external address if needed.
	if m.external.IP().IsZero() {
		if _, err := uc.WriteTo(pmpReqExternalAddrPacket, pmpAddru); err != nil {
			return netaddr.IPPort{}, err
		}
	}

	// And ask for a mapping.
	pmpReqMapping := buildPMPRequestMappingPacket(localPort, prevPort, pmpMapLifetimeSec)
	if _, err := uc.WriteTo(pmpReqMapping, pmpAddru); err != nil {
		return netaddr.IPPort{}, err
	}

	res := make([]byte, 1500)
	for {
		n, srci, err := uc.ReadFrom(res)
		if err != nil {
			if ctx.Err() == context.Canceled {
				return netaddr.IPPort{}, err
			}
			return netaddr.IPPort{}, NoMappingError{ErrNoPortMappingServices}
		}
		srcu := srci.(*net.UDPAddr)
		src, ok := netaddr.FromStdAddr(srcu.IP, srcu.Port, srcu.Zone)
		if !ok {
			continue
		}
		if src == pmpAddr {
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
				d /= 2 // renew in half the time
				m.useUntil = time.Now().Add(d)
				m.epoch = pres.SecondsSinceEpoch
			}
		}

		if m.externalValid() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.pmpMapping = m
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
		return res, ErrGatewayNotFound
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
	} else {
		uc.WriteTo(pmpReqExternalAddrPacket, pmpAddr)
	}
	if c.sawPCPRecently() {
		res.PCP = true
	} else {
		uc.WriteTo(pcpAnnounceRequest(myIP), pcpAddr)
	}
	if c.sawUPnPRecently() {
		res.UPnP = true
	} else {
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
				res.UPnP = true
				c.mu.Lock()
				c.uPnPSawTime = time.Now()
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

const (
	pcpVersion = 2
	pcpPort    = 5351

	pcpCodeOK            = 0
	pcpCodeNotAuthorized = 2

	pcpOpReply    = 0x80 // OR'd into request's op code on response
	pcpOpAnnounce = 0
	pcpOpMap      = 1
)

// pcpAnnounceRequest generates a PCP packet with an ANNOUNCE opcode.
func pcpAnnounceRequest(myIP netaddr.IP) []byte {
	// See https://tools.ietf.org/html/rfc6887#section-7.1
	pkt := make([]byte, 24)
	pkt[0] = pcpVersion // version
	pkt[1] = pcpOpAnnounce
	myIP16 := myIP.As16()
	copy(pkt[8:], myIP16[:])
	return pkt
}

//lint:ignore U1000 moved this code from netcheck's old PCP probing; will be needed when we add PCP mapping

// pcpMapRequest generates a PCP packet with a MAP opcode.
func pcpMapRequest(myIP netaddr.IP, mapToLocalPort int, delete bool) []byte {
	const udpProtoNumber = 17
	lifetimeSeconds := uint32(1)
	if delete {
		lifetimeSeconds = 0
	}
	const opMap = 1

	// 24 byte header + 36 byte map opcode
	pkt := make([]byte, (32+32+128)/8+(96+8+24+16+16+128)/8)

	// The header (https://tools.ietf.org/html/rfc6887#section-7.1)
	pkt[0] = 2 // version
	pkt[1] = opMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSeconds)
	myIP16 := myIP.As16()
	copy(pkt[8:], myIP16[:])

	// The map opcode body (https://tools.ietf.org/html/rfc6887#section-11.1)
	mapOp := pkt[24:]
	rand.Read(mapOp[:12]) // 96 bit mappping nonce
	mapOp[12] = udpProtoNumber
	binary.BigEndian.PutUint16(mapOp[16:], uint16(mapToLocalPort))
	v4unspec := netaddr.MustParseIP("0.0.0.0")
	v4unspec16 := v4unspec.As16()
	copy(mapOp[20:], v4unspec16[:])
	return pkt
}

type pcpResponse struct {
	OpCode     uint8
	ResultCode uint8
	Lifetime   uint32
	Epoch      uint32
}

func parsePCPResponse(b []byte) (res pcpResponse, ok bool) {
	if len(b) < 24 || b[0] != pcpVersion {
		return
	}
	res.OpCode = b[1]
	res.ResultCode = b[3]
	res.Lifetime = binary.BigEndian.Uint32(b[4:])
	res.Epoch = binary.BigEndian.Uint32(b[8:])
	return res, true
}

const (
	upnpPort = 1900
)

var uPnPPacket = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: ssdp:all\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n")

var pmpReqExternalAddrPacket = []byte{0, 0} // version 0, opcode 0 = "Public address request"
