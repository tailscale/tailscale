// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netcheck checks the network conditions from the current host.
package netcheck

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/tcnksm/go-httpstat"
	"go4.org/mem"
	"inet.af/netaddr"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netns"
	"tailscale.com/net/stun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
)

type Report struct {
	UDP                   bool     // UDP works
	IPv6                  bool     // IPv6 works
	IPv4                  bool     // IPv4 works
	MappingVariesByDestIP opt.Bool // for IPv4
	HairPinning           opt.Bool // for IPv4

	// UPnP is whether UPnP appears present on the LAN.
	// Empty means not checked.
	UPnP opt.Bool
	// PMP is whether NAT-PMP appears present on the LAN.
	// Empty means not checked.
	PMP opt.Bool
	// PCP is whether PCP appears present on the LAN.
	// Empty means not checked.
	PCP opt.Bool

	PreferredDERP   int                   // or 0 for unknown
	RegionLatency   map[int]time.Duration // keyed by DERP Region ID
	RegionV4Latency map[int]time.Duration // keyed by DERP Region ID
	RegionV6Latency map[int]time.Duration // keyed by DERP Region ID

	GlobalV4 string // ip:port of global IPv4
	GlobalV6 string // [ip]:port of global IPv6

	// TODO: update Clone when adding new fields
}

// AnyPortMappingChecked reports whether any of UPnP, PMP, or PCP are non-empty.
func (r *Report) AnyPortMappingChecked() bool {
	return r.UPnP != "" || r.PMP != "" || r.PCP != ""
}

func (r *Report) Clone() *Report {
	if r == nil {
		return nil
	}
	r2 := *r
	r2.RegionLatency = cloneDurationMap(r2.RegionLatency)
	r2.RegionV4Latency = cloneDurationMap(r2.RegionV4Latency)
	r2.RegionV6Latency = cloneDurationMap(r2.RegionV6Latency)
	return &r2
}

func cloneDurationMap(m map[int]time.Duration) map[int]time.Duration {
	if m == nil {
		return nil
	}
	m2 := make(map[int]time.Duration, len(m))
	for k, v := range m {
		m2[k] = v
	}
	return m2
}

// Client generates a netcheck Report.
type Client struct {
	// DNSCache optionally specifies a DNSCache to use.
	// If nil, a DNS cache is not used.
	DNSCache *dnscache.Resolver

	// Verbose enables verbose logging.
	Verbose bool

	// Logf optionally specifies where to log to.
	// If nil, log.Printf is used.
	Logf logger.Logf

	// TimeNow, if non-nil, is used instead of time.Now.
	TimeNow func() time.Time

	// GetSTUNConn4 optionally provides a func to return the
	// connection to use for sending & receiving IPv4 packets. If
	// nil, an emphemeral one is created as needed.
	GetSTUNConn4 func() STUNConn

	// GetSTUNConn6 is like GetSTUNConn4, but for IPv6.
	GetSTUNConn6 func() STUNConn

	mu       sync.Mutex            // guards following
	nextFull bool                  // do a full region scan, even if last != nil
	prev     map[time.Time]*Report // some previous reports
	last     *Report               // most recent report
	lastFull time.Time             // time of last full (non-incremental) report
	curState *reportState          // non-nil if we're in a call to GetReportn
}

// STUNConn is the interface required by the netcheck Client when
// reusing an existing UDP connection.
type STUNConn interface {
	WriteTo([]byte, net.Addr) (int, error)
	ReadFrom([]byte) (int, net.Addr, error)
}

func (c *Client) logf(format string, a ...interface{}) {
	if c.Logf != nil {
		c.Logf(format, a...)
	} else {
		log.Printf(format, a...)
	}
}

func (c *Client) vlogf(format string, a ...interface{}) {
	if c.Verbose {
		c.logf(format, a...)
	}
}

// handleHairSTUN reports whether pkt (from src) was our magic hairpin
// probe packet that we sent to ourselves.
func (c *Client) handleHairSTUNLocked(pkt []byte, src netaddr.IPPort) bool {
	rs := c.curState
	if rs == nil {
		return false
	}
	if tx, err := stun.ParseBindingRequest(pkt); err == nil && tx == rs.hairTX {
		select {
		case rs.gotHairSTUN <- src:
		default:
		}
		return true
	}
	return false
}

// MakeNextReportFull forces the next GetReport call to be a full
// (non-incremental) probe of all DERP regions.
func (c *Client) MakeNextReportFull() {
	c.mu.Lock()
	c.nextFull = true
	c.mu.Unlock()
}

func (c *Client) ReceiveSTUNPacket(pkt []byte, src netaddr.IPPort) {
	c.mu.Lock()
	if c.handleHairSTUNLocked(pkt, src) {
		c.mu.Unlock()
		return
	}
	rs := c.curState
	c.mu.Unlock()

	if rs == nil {
		return
	}

	tx, addr, port, err := stun.ParseResponse(pkt)
	if err != nil {
		c.mu.Unlock()
		if _, err := stun.ParseBindingRequest(pkt); err == nil {
			// This was probably our own netcheck hairpin
			// check probe coming in late. Ignore.
			return
		}
		c.logf("netcheck: received unexpected STUN message response from %v: %v", src, err)
		return
	}

	rs.mu.Lock()
	onDone, ok := rs.inFlight[tx]
	if ok {
		delete(rs.inFlight, tx)
	}
	rs.mu.Unlock()
	if ok {
		if ipp, ok := netaddr.FromStdAddr(addr, int(port), ""); ok {
			onDone(ipp)
		}
	}
}

// probeProto is the protocol used to time a node's latency.
type probeProto uint8

const (
	probeIPv4  probeProto = iota // STUN IPv4
	probeIPv6                    // STUN IPv6
	probeHTTPS                   // HTTPS
)

type probe struct {
	// delay is when the probe is started, relative to the time
	// that GetReport is called. One probe in each probePlan
	// should have a delay of 0. Non-zero values are for retries
	// on UDP loss or timeout.
	delay time.Duration

	// node is the name of the node name. DERP node names are globally
	// unique so there's no region ID.
	node string

	// proto is how the node should be probed.
	proto probeProto

	// wait is how long to wait until the probe is considered failed.
	// 0 means to use a default value.
	wait time.Duration
}

// probePlan is a set of node probes to run.
// The map key is a descriptive name, only used for tests.
//
// The values are logically an unordered set of tests to run concurrently.
// In practice there's some order to them based on their delay fields,
// but multiple probes can have the same delay time or be running concurrently
// both within and between sets.
//
// A set of probes is done once either one of the probes completes, or
// the next probe to run wouldn't yield any new information not
// already discovered by any previous probe in any set.
type probePlan map[string][]probe

// sortRegions returns the regions of dm first sorted
// from fastest to slowest (based on the 'last' report),
// end in regions that have no data.
func sortRegions(dm *tailcfg.DERPMap, last *Report) (prev []*tailcfg.DERPRegion) {
	prev = make([]*tailcfg.DERPRegion, 0, len(dm.Regions))
	for _, reg := range dm.Regions {
		prev = append(prev, reg)
	}
	sort.Slice(prev, func(i, j int) bool {
		da, db := last.RegionLatency[prev[i].RegionID], last.RegionLatency[prev[j].RegionID]
		if db == 0 && da != 0 {
			// Non-zero sorts before zero.
			return true
		}
		if da == 0 {
			// Zero can't sort before anything else.
			return false
		}
		return da < db
	})
	return prev
}

// numIncrementalRegions is the number of fastest regions to
// periodically re-query during incremental netcheck reports. (During
// a full report, all regions are scanned.)
const numIncrementalRegions = 3

// makeProbePlan generates the probe plan for a DERPMap, given the most
// recent report and whether IPv6 is configured on an interface.
func makeProbePlan(dm *tailcfg.DERPMap, ifState *interfaces.State, last *Report) (plan probePlan) {
	if last == nil || len(last.RegionLatency) == 0 {
		return makeProbePlanInitial(dm, ifState)
	}
	have6if := ifState.HaveV6Global
	have4if := ifState.HaveV4
	plan = make(probePlan)
	if !have4if && !have6if {
		return plan
	}
	had4 := len(last.RegionV4Latency) > 0
	had6 := len(last.RegionV6Latency) > 0
	hadBoth := have6if && had4 && had6
	for ri, reg := range sortRegions(dm, last) {
		if ri == numIncrementalRegions {
			break
		}
		var p4, p6 []probe
		do4 := have4if
		do6 := have6if

		// By default, each node only gets one STUN packet sent,
		// except the fastest two from the previous round.
		tries := 1
		isFastestTwo := ri < 2

		if isFastestTwo {
			tries = 2
		} else if hadBoth {
			// For dual stack machines, make the 3rd & slower nodes alternate
			// breetween
			if ri%2 == 0 {
				do4, do6 = true, false
			} else {
				do4, do6 = false, true
			}
		}
		if !isFastestTwo && !had6 {
			do6 = false
		}

		for try := 0; try < tries; try++ {
			if len(reg.Nodes) == 0 {
				// Shouldn't be possible.
				continue
			}
			if try != 0 && !had6 {
				do6 = false
			}
			n := reg.Nodes[try%len(reg.Nodes)]
			prevLatency := last.RegionLatency[reg.RegionID] * 120 / 100
			if prevLatency == 0 {
				prevLatency = 200 * time.Millisecond
			}
			delay := time.Duration(try) * prevLatency
			if do4 {
				p4 = append(p4, probe{delay: delay, node: n.Name, proto: probeIPv4})
			}
			if do6 {
				p6 = append(p6, probe{delay: delay, node: n.Name, proto: probeIPv6})
			}
		}
		if len(p4) > 0 {
			plan[fmt.Sprintf("region-%d-v4", reg.RegionID)] = p4
		}
		if len(p6) > 0 {
			plan[fmt.Sprintf("region-%d-v6", reg.RegionID)] = p6
		}
	}
	return plan
}

func makeProbePlanInitial(dm *tailcfg.DERPMap, ifState *interfaces.State) (plan probePlan) {
	plan = make(probePlan)

	// initialSTUNTimeout is only 100ms because some extra retransmits
	// when starting up is tolerable.
	const initialSTUNTimeout = 100 * time.Millisecond

	for _, reg := range dm.Regions {
		var p4 []probe
		var p6 []probe
		for try := 0; try < 3; try++ {
			n := reg.Nodes[try%len(reg.Nodes)]
			delay := time.Duration(try) * initialSTUNTimeout
			if ifState.HaveV4 && nodeMight4(n) {
				p4 = append(p4, probe{delay: delay, node: n.Name, proto: probeIPv4})
			}
			if ifState.HaveV6Global && nodeMight6(n) {
				p6 = append(p6, probe{delay: delay, node: n.Name, proto: probeIPv6})
			}
		}
		if len(p4) > 0 {
			plan[fmt.Sprintf("region-%d-v4", reg.RegionID)] = p4
		}
		if len(p6) > 0 {
			plan[fmt.Sprintf("region-%d-v6", reg.RegionID)] = p6
		}
	}
	return plan
}

// nodeMight6 reports whether n might reply to STUN over IPv6 based on
// its config alone, without DNS lookups. It only returns false if
// it's not explicitly disabled.
func nodeMight6(n *tailcfg.DERPNode) bool {
	if n.IPv6 == "" {
		return true
	}
	ip, _ := netaddr.ParseIP(n.IPv6)
	return ip.Is6()

}

// nodeMight4 reports whether n might reply to STUN over IPv4 based on
// its config alone, without DNS lookups. It only returns false if
// it's not explicitly disabled.
func nodeMight4(n *tailcfg.DERPNode) bool {
	if n.IPv4 == "" {
		return true
	}
	ip, _ := netaddr.ParseIP(n.IPv4)
	return ip.Is4()
}

// readPackets reads STUN packets from pc until there's an error or ctx is done.
// In either case, it closes pc.
func (c *Client) readPackets(ctx context.Context, pc net.PacketConn) {
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		pc.Close()
	}()

	var buf [64 << 10]byte
	for {
		n, addr, err := pc.ReadFrom(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.logf("ReadFrom: %v", err)
			return
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			c.logf("ReadFrom: unexpected addr %T", addr)
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			continue
		}
		if ipp, ok := netaddr.FromStdAddr(ua.IP, ua.Port, ua.Zone); ok {
			c.ReceiveSTUNPacket(pkt, ipp)
		}
	}
}

// reportState holds the state for a single invocation of Client.GetReport.
type reportState struct {
	c           *Client
	hairTX      stun.TxID
	gotHairSTUN chan netaddr.IPPort
	hairTimeout chan struct{} // closed on timeout
	pc4         STUNConn
	pc6         STUNConn
	pc4Hair     net.PacketConn
	incremental bool // doing a lite, follow-up netcheck
	stopProbeCh chan struct{}
	waitPortMap sync.WaitGroup

	mu            sync.Mutex
	sentHairCheck bool
	report        *Report                            // to be returned by GetReport
	inFlight      map[stun.TxID]func(netaddr.IPPort) // called without c.mu held
	gotEP4        string
	timers        []*time.Timer
}

func (rs *reportState) anyUDP() bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.report.UDP
}

func (rs *reportState) haveRegionLatency(regionID int) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	_, ok := rs.report.RegionLatency[regionID]
	return ok
}

// probeWouldHelp reports whether executing the given probe would
// yield any new information.
// The given node is provided just because the sole caller already has it
// and it saves a lookup.
func (rs *reportState) probeWouldHelp(probe probe, node *tailcfg.DERPNode) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	// If the probe is for a region we don't yet know about, that
	// would help.
	if _, ok := rs.report.RegionLatency[node.RegionID]; !ok {
		return true
	}

	// If the probe is for IPv6 and we don't yet have an IPv6
	// report, that would help.
	if probe.proto == probeIPv6 && len(rs.report.RegionV6Latency) == 0 {
		return true
	}

	// For IPv4, we need at least two IPv4 results overall to
	// determine whether we're behind a NAT that shows us as
	// different source IPs and/or ports depending on who we're
	// talking to. If we don't yet have two results yet
	// (MappingVariesByDestIP is blank), then another IPv4 probe
	// would be good.
	if probe.proto == probeIPv4 && rs.report.MappingVariesByDestIP == "" {
		return true
	}

	// Otherwise not interesting.
	return false
}

func (rs *reportState) startHairCheckLocked(dst netaddr.IPPort) {
	if rs.sentHairCheck || rs.incremental {
		return
	}
	rs.sentHairCheck = true
	ua := dst.UDPAddr()
	rs.pc4Hair.WriteTo(stun.Request(rs.hairTX), ua)
	rs.c.vlogf("sent haircheck to %v", ua)
	time.AfterFunc(500*time.Millisecond, func() { close(rs.hairTimeout) })
}

func (rs *reportState) waitHairCheck(ctx context.Context) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	ret := rs.report
	if rs.incremental {
		if rs.c.last != nil {
			ret.HairPinning = rs.c.last.HairPinning
		}
		return
	}
	if !rs.sentHairCheck {
		return
	}

	select {
	case <-rs.gotHairSTUN:
		ret.HairPinning.Set(true)
	case <-rs.hairTimeout:
		ret.HairPinning.Set(false)
	default:
		select {
		case <-rs.gotHairSTUN:
			ret.HairPinning.Set(true)
		case <-rs.hairTimeout:
			ret.HairPinning.Set(false)
		case <-ctx.Done():
		}
	}
}

func (rs *reportState) stopTimers() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	for _, t := range rs.timers {
		t.Stop()
	}
}

// addNodeLatency updates rs to note that node's latency is d. If ipp
// is non-zero (for all but HTTPS replies), it's recorded as our UDP
// IP:port.
func (rs *reportState) addNodeLatency(node *tailcfg.DERPNode, ipp netaddr.IPPort, d time.Duration) {
	var ipPortStr string
	if ipp != (netaddr.IPPort{}) {
		ipPortStr = net.JoinHostPort(ipp.IP.String(), fmt.Sprint(ipp.Port))
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()
	ret := rs.report

	ret.UDP = true
	updateLatency(ret.RegionLatency, node.RegionID, d)

	// Once we've heard from 3 regions, start a timer to give up
	// on the other ones.  The timer's duration is a function of
	// whether this is our initial full probe or an incremental
	// one. For incremental ones, wait for the duration of the
	// slowest region. For initial ones, double that.
	if len(ret.RegionLatency) == 3 {
		timeout := maxDurationValue(ret.RegionLatency)
		if !rs.incremental {
			timeout *= 2
		}
		rs.timers = append(rs.timers, time.AfterFunc(timeout, rs.stopProbes))
	}

	switch {
	case ipp.IP.Is6():
		updateLatency(ret.RegionV6Latency, node.RegionID, d)
		ret.IPv6 = true
		ret.GlobalV6 = ipPortStr
		// TODO: track MappingVariesByDestIP for IPv6
		// too? Would be sad if so, but who knows.
	case ipp.IP.Is4():
		updateLatency(ret.RegionV4Latency, node.RegionID, d)
		ret.IPv4 = true
		if rs.gotEP4 == "" {
			rs.gotEP4 = ipPortStr
			ret.GlobalV4 = ipPortStr
			rs.startHairCheckLocked(ipp)
		} else {
			if rs.gotEP4 != ipPortStr {
				ret.MappingVariesByDestIP.Set(true)
			} else if ret.MappingVariesByDestIP == "" {
				ret.MappingVariesByDestIP.Set(false)
			}
		}
	}
}

func (rs *reportState) stopProbes() {
	select {
	case rs.stopProbeCh <- struct{}{}:
	default:
	}
}

func (rs *reportState) setOptBool(b *opt.Bool, v bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	b.Set(v)
}

func (rs *reportState) probePortMapServices() {
	defer rs.waitPortMap.Done()
	gw, myIP, ok := interfaces.LikelyHomeRouterIP()
	if !ok {
		return
	}

	rs.setOptBool(&rs.report.UPnP, false)
	rs.setOptBool(&rs.report.PMP, false)
	rs.setOptBool(&rs.report.PCP, false)

	port1900 := netaddr.IPPort{IP: gw, Port: 1900}.UDPAddr()
	port5351 := netaddr.IPPort{IP: gw, Port: 5351}.UDPAddr()

	rs.c.logf("probePortMapServices: me %v -> gw %v", myIP, gw)

	// Create a UDP4 socket used just for querying for UPnP, NAT-PMP, and PCP.
	uc, err := netns.Listener().ListenPacket(context.Background(), "udp4", ":0")
	if err != nil {
		rs.c.logf("probePortMapServices: %v", err)
		return
	}
	defer uc.Close()
	tempPort := uc.LocalAddr().(*net.UDPAddr).Port
	uc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

	// Send request packets for all three protocols.
	uc.WriteTo(uPnPPacket, port1900)
	uc.WriteTo(pmpPacket, port5351)
	uc.WriteTo(pcpPacket(myIP, tempPort, false), port5351)

	res := make([]byte, 1500)
	for {
		n, addr, err := uc.ReadFrom(res)
		if err != nil {
			return
		}
		switch addr.(*net.UDPAddr).Port {
		case 1900:
			if mem.Contains(mem.B(res[:n]), mem.S(":InternetGatewayDevice:")) {
				rs.setOptBool(&rs.report.UPnP, true)
			}
		case 5351:
			if n == 12 && res[0] == 0x00 { // right length and version 0
				rs.setOptBool(&rs.report.PMP, true)
			}
			if n == 60 && res[0] == 0x02 { // right length and version 2
				rs.setOptBool(&rs.report.PCP, true)
				// Delete the mapping.
				uc.WriteTo(pcpPacket(myIP, tempPort, true), port5351)
			}
		}
	}
}

var pmpPacket = []byte{0, 0} // version 0, opcode 0 = "Public address request"

var uPnPPacket = []byte("M-SEARCH * HTTP/1.1\r\n" +
	"HOST: 239.255.255.250:1900\r\n" +
	"ST: ssdp:all\r\n" +
	"MAN: \"ssdp:discover\"\r\n" +
	"MX: 2\r\n\r\n")

var v4unspec, _ = netaddr.ParseIP("0.0.0.0")

func pcpPacket(myIP netaddr.IP, mapToLocalPort int, delete bool) []byte {
	const udpProtoNumber = 17
	lifetimeSeconds := uint32(1)
	if delete {
		lifetimeSeconds = 0
	}
	const opMap = 1
	pkt := make([]byte, (32+32+128)/8+(96+8+24+16+16+128)/8)
	pkt[0] = 2 // version
	pkt[1] = opMap
	binary.BigEndian.PutUint32(pkt[4:8], lifetimeSeconds)
	myIP16 := myIP.As16()
	copy(pkt[8:], myIP16[:])
	rand.Read(pkt[24 : 24+12])
	pkt[36] = udpProtoNumber
	binary.BigEndian.PutUint16(pkt[40:], uint16(mapToLocalPort))
	v4unspec16 := v4unspec.As16()
	copy(pkt[40:], v4unspec16[:])
	return pkt
}

func newReport() *Report {
	return &Report{
		RegionLatency:   make(map[int]time.Duration),
		RegionV4Latency: make(map[int]time.Duration),
		RegionV6Latency: make(map[int]time.Duration),
	}
}

// GetReport gets a report.
//
// It may not be called concurrently with itself.
func (c *Client) GetReport(ctx context.Context, dm *tailcfg.DERPMap) (*Report, error) {
	// Wait for STUN for 3 seconds, but then give HTTP probing
	// another 2 seconds if all UDP failed.
	const overallTimeout = 5 * time.Second
	const stunTimeout = 3 * time.Second

	// Mask user context with ours that we guarantee to cancel so
	// we can depend on it being closed in goroutines later.
	// (User ctx might be context.Background, etc)
	ctx, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()

	if dm == nil {
		return nil, errors.New("netcheck: GetReport: DERP map is nil")
	}

	c.mu.Lock()
	if c.curState != nil {
		c.mu.Unlock()
		return nil, errors.New("invalid concurrent call to GetReport")
	}
	rs := &reportState{
		c:           c,
		report:      newReport(),
		inFlight:    map[stun.TxID]func(netaddr.IPPort){},
		hairTX:      stun.NewTxID(), // random payload
		gotHairSTUN: make(chan netaddr.IPPort, 1),
		hairTimeout: make(chan struct{}),
		stopProbeCh: make(chan struct{}, 1),
	}
	c.curState = rs
	last := c.last
	now := c.timeNow()
	if c.nextFull || now.Sub(c.lastFull) > 5*time.Minute {
		last = nil // causes makeProbePlan below to do a full (initial) plan
		c.nextFull = false
		c.lastFull = now
	}
	rs.incremental = last != nil
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.curState = nil
	}()

	ifState, err := interfaces.GetState()
	if err != nil {
		c.logf("interfaces: %v", err)
		return nil, err
	}

	// Create a UDP4 socket used for sending to our discovered IPv4 address.
	rs.pc4Hair, err = netns.Listener().ListenPacket(ctx, "udp4", ":0")
	if err != nil {
		c.logf("udp4: %v", err)
		return nil, err
	}
	defer rs.pc4Hair.Close()

	rs.waitPortMap.Add(1)
	go rs.probePortMapServices()

	// At least the Apple Airport Extreme doesn't allow hairpin
	// sends from a private socket until it's seen traffic from
	// that src IP:port to something else out on the internet.
	//
	// See https://github.com/tailscale/tailscale/issues/188#issuecomment-600728643
	//
	// And it seems that even sending to a likely-filtered RFC 5737
	// documentation-only IPv4 range is enough to set up the mapping.
	// So do that for now. In the future we might want to classify networks
	// that do and don't require this separately. But for now help it.
	const documentationIP = "203.0.113.1"
	rs.pc4Hair.WriteTo([]byte("tailscale netcheck; see https://github.com/tailscale/tailscale/issues/188"), &net.UDPAddr{IP: net.ParseIP(documentationIP), Port: 12345})

	if f := c.GetSTUNConn4; f != nil {
		rs.pc4 = f()
	} else {
		u4, err := netns.Listener().ListenPacket(ctx, "udp4", ":0")
		if err != nil {
			c.logf("udp4: %v", err)
			return nil, err
		}
		rs.pc4 = u4
		go c.readPackets(ctx, u4)
	}

	if ifState.HaveV6Global {
		if f := c.GetSTUNConn6; f != nil {
			rs.pc6 = f()
		} else {
			u6, err := netns.Listener().ListenPacket(ctx, "udp6", ":0")
			if err != nil {
				c.logf("udp6: %v", err)
			} else {
				rs.pc6 = u6
				go c.readPackets(ctx, u6)
			}
		}
	}

	plan := makeProbePlan(dm, ifState, last)

	wg := syncs.NewWaitGroupChan()
	wg.Add(len(plan))
	for _, probeSet := range plan {
		setCtx, cancelSet := context.WithCancel(ctx)
		go func(probeSet []probe) {
			for _, probe := range probeSet {
				go rs.runProbe(setCtx, dm, probe, cancelSet)
			}
			<-setCtx.Done()
			wg.Decr()
		}(probeSet)
	}

	stunTimer := time.NewTimer(stunTimeout)
	defer stunTimer.Stop()

	select {
	case <-stunTimer.C:
	case <-ctx.Done():
	case <-wg.DoneChan():
	case <-rs.stopProbeCh:
		// Saw enough regions.
		c.vlogf("saw enough regions; not waiting for rest")
	}

	rs.waitHairCheck(ctx)
	rs.waitPortMap.Wait()
	rs.stopTimers()

	// Try HTTPS latency check if all STUN probes failed due to UDP presumably being blocked.
	// TODO: this should be moved into the probePlan, using probeProto probeHTTPS.
	if !rs.anyUDP() && ctx.Err() == nil {
		var wg sync.WaitGroup
		var need []*tailcfg.DERPRegion
		for rid, reg := range dm.Regions {
			if !rs.haveRegionLatency(rid) && regionHasDERPNode(reg) {
				need = append(need, reg)
			}
		}
		if len(need) > 0 {
			wg.Add(len(need))
			c.logf("netcheck: UDP is blocked, trying HTTPS")
		}
		for _, reg := range need {
			go func(reg *tailcfg.DERPRegion) {
				defer wg.Done()
				if d, ip, err := c.measureHTTPSLatency(ctx, reg); err != nil {
					c.logf("netcheck: measuring HTTPS latency of %v (%d): %v", reg.RegionCode, reg.RegionID, err)
				} else {
					rs.mu.Lock()
					rs.report.RegionLatency[reg.RegionID] = d
					// We set these IPv4 and IPv6 but they're not really used
					// and we don't necessarily set them both. If UDP is blocked
					// and both IPv4 and IPv6 are available over TCP, it's basically
					// random which fields end up getting set here.
					// Since they're not needed, that's fine for now.
					if ip.Is4() {
						rs.report.IPv4 = true
					}
					if ip.Is6() {
						rs.report.IPv6 = true
					}
					rs.mu.Unlock()
				}
			}(reg)
		}
		wg.Wait()
	}

	rs.mu.Lock()
	report := rs.report.Clone()
	rs.mu.Unlock()

	c.addReportHistoryAndSetPreferredDERP(report)
	c.logConciseReport(report, dm)

	return report, nil
}

func (c *Client) measureHTTPSLatency(ctx context.Context, reg *tailcfg.DERPRegion) (time.Duration, netaddr.IP, error) {
	var result httpstat.Result
	ctx, cancel := context.WithTimeout(httpstat.WithHTTPStat(ctx, &result), 5*time.Second)
	defer cancel()

	var ip netaddr.IP

	dc := derphttp.NewNetcheckClient(c.logf)
	tlsConn, tcpConn, err := dc.DialRegionTLS(ctx, reg)
	if err != nil {
		return 0, ip, err
	}
	defer tcpConn.Close()

	if ta, ok := tlsConn.RemoteAddr().(*net.TCPAddr); ok {
		ip, _ = netaddr.FromStdIP(ta.IP)
	}
	if ip == (netaddr.IP{}) {
		return 0, ip, fmt.Errorf("no unexpected RemoteAddr %#v", tlsConn.RemoteAddr())
	}

	connc := make(chan *tls.Conn, 1)
	connc <- tlsConn

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("unexpected DialContext dial")
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			select {
			case nc := <-connc:
				return nc, nil
			default:
				return nil, errors.New("only one conn expected")
			}
		},
	}
	hc := &http.Client{Transport: tr}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://derp-unused-hostname.tld/derp/latency-check", nil)
	if err != nil {
		return 0, ip, err
	}

	resp, err := hc.Do(req)
	if err != nil {
		return 0, ip, err
	}
	defer resp.Body.Close()

	_, err = io.Copy(ioutil.Discard, io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return 0, ip, err
	}
	result.End(c.timeNow())

	// TODO: decide best timing heuristic here.
	// Maybe the server should return the tcpinfo_rtt?
	return result.ServerProcessing, ip, nil
}

func (c *Client) logConciseReport(r *Report, dm *tailcfg.DERPMap) {
	c.logf("%v", logger.ArgWriter(func(w *bufio.Writer) {
		fmt.Fprintf(w, "udp=%v", r.UDP)
		if !r.IPv4 {
			fmt.Fprintf(w, " v4=%v", r.IPv4)
		}

		fmt.Fprintf(w, " v6=%v", r.IPv6)
		fmt.Fprintf(w, " mapvarydest=%v", r.MappingVariesByDestIP)
		fmt.Fprintf(w, " hair=%v", r.HairPinning)
		if r.AnyPortMappingChecked() {
			fmt.Fprintf(w, " portmap=%v%v%v", conciseOptBool(r.UPnP, "U"), conciseOptBool(r.PMP, "M"), conciseOptBool(r.PCP, "C"))
		} else {
			fmt.Fprintf(w, " portmap=?")
		}
		if r.GlobalV4 != "" {
			fmt.Fprintf(w, " v4a=%v", r.GlobalV4)
		}
		if r.GlobalV6 != "" {
			fmt.Fprintf(w, " v6a=%v", r.GlobalV6)
		}
		fmt.Fprintf(w, " derp=%v", r.PreferredDERP)
		if r.PreferredDERP != 0 {
			fmt.Fprintf(w, " derpdist=")
			needComma := false
			for _, rid := range dm.RegionIDs() {
				if d := r.RegionV4Latency[rid]; d != 0 {
					if needComma {
						w.WriteByte(',')
					}
					fmt.Fprintf(w, "%dv4:%v", rid, d.Round(time.Millisecond))
					needComma = true
				}
				if d := r.RegionV6Latency[rid]; d != 0 {
					if needComma {
						w.WriteByte(',')
					}
					fmt.Fprintf(w, "%dv6:%v", rid, d.Round(time.Millisecond))
					needComma = true
				}
			}
		}
	}))
}

func (c *Client) timeNow() time.Time {
	if c.TimeNow != nil {
		return c.TimeNow()
	}
	return time.Now()
}

// addReportHistoryAndSetPreferredDERP adds r to the set of recent Reports
// and mutates r.PreferredDERP to contain the best recent one.
func (c *Client) addReportHistoryAndSetPreferredDERP(r *Report) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.prev == nil {
		c.prev = map[time.Time]*Report{}
	}
	now := c.timeNow()
	c.prev[now] = r
	c.last = r

	const maxAge = 5 * time.Minute

	// region ID => its best recent latency in last maxAge
	bestRecent := map[int]time.Duration{}

	for t, pr := range c.prev {
		if now.Sub(t) > maxAge {
			delete(c.prev, t)
			continue
		}
		for hp, d := range pr.RegionLatency {
			if bd, ok := bestRecent[hp]; !ok || d < bd {
				bestRecent[hp] = d
			}
		}
	}

	// Then, pick which currently-alive DERP server from the
	// current report has the best latency over the past maxAge.
	var bestAny time.Duration
	for hp := range r.RegionLatency {
		best := bestRecent[hp]
		if r.PreferredDERP == 0 || best < bestAny {
			bestAny = best
			r.PreferredDERP = hp
		}
	}
}

func updateLatency(m map[int]time.Duration, regionID int, d time.Duration) {
	if prev, ok := m[regionID]; !ok || d < prev {
		m[regionID] = d
	}
}

func namedNode(dm *tailcfg.DERPMap, nodeName string) *tailcfg.DERPNode {
	if dm == nil {
		return nil
	}
	for _, r := range dm.Regions {
		for _, n := range r.Nodes {
			if n.Name == nodeName {
				return n
			}
		}
	}
	return nil
}

func (rs *reportState) runProbe(ctx context.Context, dm *tailcfg.DERPMap, probe probe, cancelSet func()) {
	c := rs.c
	node := namedNode(dm, probe.node)
	if node == nil {
		c.logf("netcheck.runProbe: named node %q not found", probe.node)
		return
	}

	if probe.delay > 0 {
		delayTimer := time.NewTimer(probe.delay)
		select {
		case <-delayTimer.C:
		case <-ctx.Done():
			delayTimer.Stop()
			return
		}
	}

	if !rs.probeWouldHelp(probe, node) {
		cancelSet()
		return
	}

	addr := c.nodeAddr(ctx, node, probe.proto)
	if addr == nil {
		return
	}

	txID := stun.NewTxID()
	req := stun.Request(txID)

	sent := time.Now() // after DNS lookup above

	rs.mu.Lock()
	rs.inFlight[txID] = func(ipp netaddr.IPPort) {
		rs.addNodeLatency(node, ipp, time.Since(sent))
		cancelSet() // abort other nodes in this set
	}
	rs.mu.Unlock()

	switch probe.proto {
	case probeIPv4:
		rs.pc4.WriteTo(req, addr)
	case probeIPv6:
		rs.pc6.WriteTo(req, addr)
	default:
		panic("bad probe proto " + fmt.Sprint(probe.proto))
	}
	c.vlogf("sent to %v", addr)
}

// proto is 4 or 6
// If it returns nil, the node is skipped.
func (c *Client) nodeAddr(ctx context.Context, n *tailcfg.DERPNode, proto probeProto) *net.UDPAddr {
	port := n.STUNPort
	if port == 0 {
		port = 3478
	}
	if port < 0 || port > 1<<16-1 {
		return nil
	}
	switch proto {
	case probeIPv4:
		if n.IPv4 != "" {
			ip, _ := netaddr.ParseIP(n.IPv4)
			if !ip.Is4() {
				return nil
			}
			return netaddr.IPPort{ip, uint16(port)}.UDPAddr()
		}
	case probeIPv6:
		if n.IPv6 != "" {
			ip, _ := netaddr.ParseIP(n.IPv6)
			if !ip.Is6() {
				return nil
			}
			return netaddr.IPPort{ip, uint16(port)}.UDPAddr()
		}
	default:
		return nil
	}

	// TODO(bradfitz): add singleflight+dnscache here.
	addrs, _ := net.DefaultResolver.LookupIPAddr(ctx, n.HostName)
	for _, a := range addrs {
		if (a.IP.To4() != nil) == (proto == probeIPv4) {
			return &net.UDPAddr{IP: a.IP, Port: port}
		}
	}
	return nil
}

func regionHasDERPNode(r *tailcfg.DERPRegion) bool {
	for _, n := range r.Nodes {
		if !n.STUNOnly {
			return true
		}
	}
	return false
}

func maxDurationValue(m map[int]time.Duration) (max time.Duration) {
	for _, v := range m {
		if v > max {
			max = v
		}
	}
	return max
}

func conciseOptBool(b opt.Bool, trueVal string) string {
	if b == "" {
		return "_"
	}
	v, ok := b.Get()
	if !ok {
		return "x"
	}
	if v {
		return trueVal
	}
	return ""
}
