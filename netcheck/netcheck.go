// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netcheck checks the network conditions from the current host.
package netcheck

import (
	"bytes"
	"context"
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
	"inet.af/netaddr"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/interfaces"
	"tailscale.com/stun"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
)

type Report struct {
	UDP                   bool                  // UDP works
	IPv6                  bool                  // IPv6 works
	MappingVariesByDestIP opt.Bool              // for IPv4
	HairPinning           opt.Bool              // for IPv4
	PreferredDERP         int                   // or 0 for unknown
	RegionLatency         map[int]time.Duration // keyed by DERP Region ID
	RegionV4Latency       map[int]time.Duration // keyed by DERP Region ID
	RegionV6Latency       map[int]time.Duration // keyed by DERP Region ID

	GlobalV4 string // ip:port of global IPv4
	GlobalV6 string // [ip]:port of global IPv6

	// TODO: update Clone when adding new fields
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
	prev     map[time.Time]*Report // some previous reports
	last     *Report               // most recent report
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

// handleHairSTUN reports whether pkt (from src) was our magic hairpin
// probe packet that we sent to ourselves.
func (c *Client) handleHairSTUNLocked(pkt []byte, src *net.UDPAddr) bool {
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

func (c *Client) ReceiveSTUNPacket(pkt []byte, src *net.UDPAddr) {
	if src == nil || src.IP == nil {
		panic("bogus src")
	}

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

// makePlan generates the probe plan for a DERPMap, given the most
// recent report and whether IPv6 is configured on an interface.
func makeProbePlan(dm *tailcfg.DERPMap, have6if bool, last *Report) (plan probePlan) {
	if last == nil || len(last.RegionLatency) == 0 {
		return makeProbePlanInitial(dm, have6if)
	}
	plan = make(probePlan)
	had4 := len(last.RegionV4Latency) > 0
	had6 := len(last.RegionV6Latency) > 0
	hadBoth := have6if && had4 && had6
	for ri, reg := range sortRegions(dm, last) {
		var p4, p6 []probe
		do4 := true
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

func makeProbePlanInitial(dm *tailcfg.DERPMap, have6if bool) (plan probePlan) {
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
			if nodeMight4(n) {
				p4 = append(p4, probe{delay: delay, node: n.Name, proto: probeIPv4})
			}
			if have6if && nodeMight6(n) {
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
		c.ReceiveSTUNPacket(pkt, ua)
	}
}

// reportState holds the state for a single invocation of Client.GetReport.
type reportState struct {
	c           *Client
	hairTX      stun.TxID
	gotHairSTUN chan *net.UDPAddr
	hairTimeout chan struct{} // closed on timeout
	pc4         STUNConn
	pc6         STUNConn
	pc4Hair     net.PacketConn

	mu            sync.Mutex
	sentHairCheck bool
	report        *Report                            // to be returned by GetReport
	inFlight      map[stun.TxID]func(netaddr.IPPort) // called without c.mu held
	gotEP4        string
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

	// If the probe is for IPv6 and we don't
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
	if rs.sentHairCheck {
		return
	}
	rs.sentHairCheck = true
	rs.pc4Hair.WriteTo(stun.Request(rs.hairTX), dst.UDPAddr())
	time.AfterFunc(500*time.Millisecond, func() { close(rs.hairTimeout) })
}

func (rs *reportState) waitHairCheck(ctx context.Context) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if !rs.sentHairCheck {
		return
	}
	ret := rs.report

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
	updateLatency(&ret.RegionLatency, node.RegionID, d)

	switch {
	case ipp.IP.Is6():
		updateLatency(&ret.RegionV6Latency, node.RegionID, d)
		ret.IPv6 = true
		ret.GlobalV6 = ipPortStr
		// TODO: track MappingVariesByDestIP for IPv6
		// too? Would be sad if so, but who knows.
	case ipp.IP.Is4():
		updateLatency(&ret.RegionV4Latency, node.RegionID, d)
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

// GetReport gets a report.
//
// It may not be called concurrently with itself.
func (c *Client) GetReport(ctx context.Context, dm *tailcfg.DERPMap) (*Report, error) {
	// Mask user context with ours that we guarantee to cancel so
	// we can depend on it being closed in goroutines later.
	// (User ctx might be context.Background, etc)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
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
		report:      new(Report),
		inFlight:    map[stun.TxID]func(netaddr.IPPort){},
		hairTX:      stun.NewTxID(), // random payload
		gotHairSTUN: make(chan *net.UDPAddr, 1),
		hairTimeout: make(chan struct{}),
	}
	c.curState = rs
	last := c.last
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.curState = nil
	}()

	v6iface, err := interfaces.HaveIPv6GlobalAddress()
	if err != nil {
		c.logf("interfaces: %v", err)
	}

	// Create a UDP4 socket used for sending to our discovered IPv4 address.
	rs.pc4Hair, err = net.ListenPacket("udp4", ":0")
	if err != nil {
		c.logf("udp4: %v", err)
		return nil, err
	}
	defer rs.pc4Hair.Close()

	if f := c.GetSTUNConn4; f != nil {
		rs.pc4 = f()
	} else {
		u4, err := net.ListenPacket("udp4", ":0")
		if err != nil {
			c.logf("udp4: %v", err)
			return nil, err
		}
		rs.pc4 = u4
		go c.readPackets(ctx, u4)
	}

	if v6iface {
		if f := c.GetSTUNConn6; f != nil {
			rs.pc6 = f()
		} else {
			u6, err := net.ListenPacket("udp6", ":0")
			if err != nil {
				c.logf("udp6: %v", err)
			} else {
				rs.pc6 = u6
				go c.readPackets(ctx, u6)
			}
		}
	}

	plan := makeProbePlan(dm, v6iface, last)

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

	select {
	case <-ctx.Done():
	case <-wg.DoneChan():
	}

	rs.waitHairCheck(ctx)

	// Try HTTPS latency check if all STUN probes failed due to UDP presumably being blocked.
	if !rs.anyUDP() {
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
				if d, err := c.measureHTTPSLatency(reg); err != nil {
					c.logf("netcheck: measuring HTTPS latency of %v (%d): %v", reg.RegionCode, reg.RegionID, err)
				} else {
					rs.mu.Lock()
					rs.report.RegionLatency[reg.RegionID] = d
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

// TODO: have caller pass in context
func (c *Client) measureHTTPSLatency(reg *tailcfg.DERPRegion) (time.Duration, error) {
	if len(reg.Nodes) == 0 {
		return 0, errors.New("no nodes")
	}
	node := reg.Nodes[0] // TODO: use all nodes per region
	host := node.HostName
	// TODO: connect using provided IPv4/IPv6; use a Trasport & set the dialer

	var result httpstat.Result
	hctx, cancel := context.WithTimeout(httpstat.WithHTTPStat(context.Background(), &result), 5*time.Second)
	defer cancel()

	u := fmt.Sprintf("https://%s/derp/latency-check", host)
	req, err := http.NewRequestWithContext(hctx, "GET", u, nil)
	if err != nil {
		return 0, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	_, err = io.Copy(ioutil.Discard, resp.Body)
	if err != nil {
		return 0, err
	}
	result.End(c.timeNow())

	// TODO: decide best timing heuristic here.
	// Maybe the server should return the tcpinfo_rtt?
	return result.ServerProcessing, nil
}

func (c *Client) logConciseReport(r *Report, dm *tailcfg.DERPMap) {
	buf := bytes.NewBuffer(make([]byte, 0, 256)) // empirically: 5 DERPs + IPv6 == ~233 bytes
	fmt.Fprintf(buf, "udp=%v", r.UDP)
	fmt.Fprintf(buf, " v6=%v", r.IPv6)
	fmt.Fprintf(buf, " mapvarydest=%v", r.MappingVariesByDestIP)
	fmt.Fprintf(buf, " hair=%v", r.HairPinning)
	if r.GlobalV4 != "" {
		fmt.Fprintf(buf, " v4a=%v", r.GlobalV4)
	}
	if r.GlobalV6 != "" {
		fmt.Fprintf(buf, " v6a=%v", r.GlobalV6)
	}
	fmt.Fprintf(buf, " derp=%v", r.PreferredDERP)
	if r.PreferredDERP != 0 {
		fmt.Fprintf(buf, " derpdist=")
		for i, rid := range dm.RegionIDs() {
			if i != 0 {
				buf.WriteByte(',')
			}
			needComma := false
			if d := r.RegionV4Latency[rid]; d != 0 {
				fmt.Fprintf(buf, "%dv4:%v", rid, d.Round(time.Millisecond))
				needComma = true
			}
			if d := r.RegionV6Latency[rid]; d != 0 {
				if needComma {
					buf.WriteByte(',')
				}
				fmt.Fprintf(buf, "%dv6:%v", rid, d.Round(time.Millisecond))
			}
		}
	}

	c.logf("%s", buf.Bytes())
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

func updateLatency(mp *map[int]time.Duration, regionID int, d time.Duration) {
	if *mp == nil {
		*mp = make(map[int]time.Duration)
	}
	m := *mp
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
