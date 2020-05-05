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
	"log"
	"net"
	"sort"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/derp/derpmap"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/interfaces"
	"tailscale.com/stun"
	"tailscale.com/stunner"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
)

type Report struct {
	UDP                   bool                     // UDP works
	IPv6                  bool                     // IPv6 works
	MappingVariesByDestIP opt.Bool                 // for IPv4
	HairPinning           opt.Bool                 // for IPv4
	PreferredDERP         int                      // or 0 for unknown
	DERPLatency           map[string]time.Duration // keyed by STUN host:port

	GlobalV4 string // ip:port of global IPv4
	GlobalV6 string // [ip]:port of global IPv6 // TODO

	// TODO: update Clone when adding new fields
}

func (r *Report) Clone() *Report {
	if r == nil {
		return nil
	}
	r2 := *r
	if r2.DERPLatency != nil {
		r2.DERPLatency = map[string]time.Duration{}
		for k, v := range r.DERPLatency {
			r2.DERPLatency[k] = v
		}
	}
	return &r2
}

// Client generates a netcheck Report.
type Client struct {
	// DERP is the DERP world to use.
	DERP *derpmap.World

	// DNSCache optionally specifies a DNSCache to use.
	// If nil, a DNS cache is not used.
	DNSCache *dnscache.Resolver

	// Logf optionally specifies where to log to.
	Logf logger.Logf

	// TimeNow, if non-nil, is used instead of time.Now.
	TimeNow func() time.Time

	GetSTUNConn4 func() STUNConn
	GetSTUNConn6 func() STUNConn

	mu          sync.Mutex            // guards following
	prev        map[time.Time]*Report // some previous reports
	last        *Report               // most recent report
	s4          *stunner.Stunner
	s6          *stunner.Stunner
	hairTX      stun.TxID
	gotHairSTUN chan *net.UDPAddr // non-nil if we're in GetReport
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
func (c *Client) handleHairSTUN(pkt []byte, src *net.UDPAddr) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handleHairSTUNLocked(pkt, src)
}

func (c *Client) handleHairSTUNLocked(pkt []byte, src *net.UDPAddr) bool {
	if tx, err := stun.ParseBindingRequest(pkt); err == nil && tx == c.hairTX {
		select {
		case c.gotHairSTUN <- src:
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

	var st *stunner.Stunner
	if src.IP.To4() != nil {
		st = c.s4
	} else {
		st = c.s6
	}

	c.mu.Unlock()

	if st != nil {
		st.Receive(pkt, src)
	}
}

// pickSubset selects a subset of IPv4 and IPv6 STUN server addresses
// to hit based on history.
//
// maxTries is the max number of tries per server.
//
// The caller owns the returned values.
func (c *Client) pickSubset() (stuns4, stuns6 []string, maxTries map[string]int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	const defaultMaxTries = 2
	maxTries = map[string]int{}

	var prev4, prev6 []string // sorted fastest to slowest
	if c.last != nil {
		condAppend := func(dst []string, server string) []string {
			if server != "" && c.last.DERPLatency[server] != 0 {
				return append(dst, server)
			}
			return dst
		}
		c.DERP.ForeachServer(func(s *derpmap.Server) {
			prev4 = condAppend(prev4, s.STUN4)
			prev6 = condAppend(prev6, s.STUN6)
		})
		sort.Slice(prev4, func(i, j int) bool { return c.last.DERPLatency[prev4[i]] < c.last.DERPLatency[prev4[j]] })
		sort.Slice(prev6, func(i, j int) bool { return c.last.DERPLatency[prev6[i]] < c.last.DERPLatency[prev6[j]] })
	}

	c.DERP.ForeachServer(func(s *derpmap.Server) {
		if s.STUN4 == "" {
			return
		}
		// STUN against all DERP's IPv4 endpoints, but
		// if the previous report had results from
		// more than 2 servers, only do 1 try against
		// all but the first two.
		stuns4 = append(stuns4, s.STUN4)
		tries := defaultMaxTries
		if len(prev4) > 2 && !stringsContains(prev4[:2], s.STUN4) {
			tries = 1
		}
		maxTries[s.STUN4] = tries
		if s.STUN6 != "" && tries == defaultMaxTries {
			// For IPv6, we mostly care whether the user has IPv6 at all,
			// so we don't need to send to all servers. The IPv4 timing
			// information is enough for now. (We don't yet support IPv6-only)
			// So only add the two fastest ones, or all if this is a fresh one.
			stuns6 = append(stuns6, s.STUN6)
			maxTries[s.STUN6] = 1
		}
	})

	if len(stuns4) == 0 {
		// TODO: make this work? if we ever need it
		// to. Requirement for self-hosted Tailscale might be
		// to run a DERP+STUN server co-resident with the
		// Control server.
		return nil, nil, nil, errors.New("netcheck: GetReport: no STUN servers, no Report")
	}
	sort.Strings(stuns4)
	sort.Strings(stuns6)
	return stuns4, stuns6, maxTries, nil
}

// GetReport gets a report.
//
// It may not be called concurrently with itself.
func (c *Client) GetReport(ctx context.Context) (*Report, error) {
	// Mask user context with ours that we guarantee to cancel so
	// we can depend on it being closed in goroutines later.
	// (User ctx might be context.Background, etc)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if c.DERP == nil {
		return nil, errors.New("netcheck: GetReport: Client.DERP is nil")
	}

	c.mu.Lock()
	if c.gotHairSTUN != nil {
		c.mu.Unlock()
		return nil, errors.New("invalid concurrent call to GetReport")
	}
	hairTX := stun.NewTxID() // random payload
	c.hairTX = hairTX
	gotHairSTUN := make(chan *net.UDPAddr, 1)
	c.gotHairSTUN = gotHairSTUN
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.s4 = nil
		c.s6 = nil
		c.gotHairSTUN = nil
	}()

	stuns4, stuns6, maxTries, err := c.pickSubset()
	if err != nil {
		return nil, err
	}

	closeOnCtx := func(c io.Closer) {
		<-ctx.Done()
		c.Close()
	}

	v6iface, err := interfaces.HaveIPv6GlobalAddress()
	if err != nil {
		c.logf("interfaces: %v", err)
	}

	// Create a UDP4 socket used for sending to our discovered IPv4 address.
	pc4Hair, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		c.logf("udp4: %v", err)
		return nil, err
	}
	defer pc4Hair.Close()
	hairTimeout := make(chan bool, 1)
	startHairCheck := func(dstEP string) {
		if dst, err := net.ResolveUDPAddr("udp4", dstEP); err == nil {
			pc4Hair.WriteTo(stun.Request(hairTX), dst)
			time.AfterFunc(500*time.Millisecond, func() { hairTimeout <- true })
		}
	}

	var (
		mu  sync.Mutex
		ret = &Report{
			DERPLatency: map[string]time.Duration{},
		}
		gotEP  = map[string]string{} // server -> ipPort
		gotEP4 string
	)
	anyV6 := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return ret.IPv6
	}
	anyV4 := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotEP4 != ""
	}
	add := func(server, ipPort string, d time.Duration) {
		ua, err := net.ResolveUDPAddr("udp", ipPort)
		if err != nil {
			c.logf("[unexpected] STUN addr %q", ipPort)
			return
		}
		isV6 := ua.IP.To4() == nil

		mu.Lock()
		defer mu.Unlock()
		ret.UDP = true
		ret.DERPLatency[server] = d
		if isV6 {
			ret.IPv6 = true
			ret.GlobalV6 = ipPort
			// TODO: track MappingVariesByDestIP for IPv6
			// too? Would be sad if so, but who knows.
		} else {
			// IPv4
			if gotEP4 == "" {
				gotEP4 = ipPort
				ret.GlobalV4 = ipPort
				startHairCheck(ipPort)
			} else {
				if gotEP4 != ipPort {
					ret.MappingVariesByDestIP.Set(true)
				} else if ret.MappingVariesByDestIP == "" {
					ret.MappingVariesByDestIP.Set(false)
				}
			}
		}
		gotEP[server] = ipPort
	}

	var pc4, pc6 STUNConn

	if f := c.GetSTUNConn4; f != nil {
		pc4 = f()
	} else {
		u4, err := net.ListenPacket("udp4", ":0")
		if err != nil {
			c.logf("udp4: %v", err)
			return nil, err
		}
		pc4 = u4
		go closeOnCtx(u4)
	}

	if v6iface {
		if f := c.GetSTUNConn6; f != nil {
			pc6 = f()
		} else {
			u6, err := net.ListenPacket("udp6", ":0")
			if err != nil {
				c.logf("udp6: %v", err)
			} else {
				pc6 = u6
				go closeOnCtx(u6)
			}
		}
	}

	reader := func(s *stunner.Stunner, pc STUNConn) {
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
			if c.handleHairSTUN(buf[:n], ua) {
				continue
			}
			s.Receive(buf[:n], ua)
		}

	}

	var grp errgroup.Group

	s4 := &stunner.Stunner{
		Send:     pc4.WriteTo,
		Endpoint: add,
		Servers:  stuns4,
		Logf:     c.logf,
		DNSCache: dnscache.Get(),
		MaxTries: maxTries,
	}

	c.mu.Lock()
	c.s4 = s4
	c.mu.Unlock()

	grp.Go(func() error {
		err := s4.Run(ctx)
		if errors.Is(err, context.DeadlineExceeded) {
			if !anyV4() {
				c.logf("netcheck: no IPv4 UDP STUN replies")
			}
			return nil
		}
		return err
	})
	if c.GetSTUNConn4 == nil {
		go reader(s4, pc4)
	}

	if pc6 != nil && len(stuns6) > 0 {
		s6 := &stunner.Stunner{
			Endpoint: add,
			Send:     pc6.WriteTo,
			Servers:  stuns6,
			Logf:     c.logf,
			OnlyIPv6: true,
			DNSCache: dnscache.Get(),
			MaxTries: maxTries,
		}

		c.mu.Lock()
		c.s6 = s6
		c.mu.Unlock()

		grp.Go(func() error {
			err := s6.Run(ctx)
			if errors.Is(err, context.DeadlineExceeded) {
				if !anyV6() {
					// IPv6 seemed like it was configured, but actually failed.
					// Just log and return a nil error.
					c.logf("IPv6 seemed configured, but no UDP STUN replies")
				}
				return nil
			}
			// Otherwise must be some invalid use of Stunner.
			return err //
		})
		if c.GetSTUNConn6 == nil {
			go reader(s6, pc6)
		}
	}

	err = grp.Wait()
	if err != nil {
		return nil, err
	}

	mu.Lock()
	defer mu.Unlock()

	// Check hairpinning.
	if ret.MappingVariesByDestIP == "false" && gotEP4 != "" {
		select {
		case <-gotHairSTUN:
			ret.HairPinning.Set(true)
		case <-hairTimeout:
			ret.HairPinning.Set(false)
		}
	}

	// TODO: if UDP is blocked, try to measure TCP connect times
	// to DERP nodes instead? So UDP-blocked users still get a
	// decent DERP node, rather than being randomly assigned to
	// the other side of the planet? Or try ICMP? (likely also
	// blocked?)

	report := ret.Clone()

	c.addReportHistoryAndSetPreferredDERP(report)
	c.logConciseReport(report)

	return report, nil
}

func (c *Client) logConciseReport(r *Report) {
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
		for i, id := range c.DERP.IDs() {
			if i != 0 {
				buf.WriteByte(',')
			}
			s := c.DERP.ServerByID(id)
			needComma := false
			if d := r.DERPLatency[s.STUN4]; d != 0 {
				fmt.Fprintf(buf, "%dv4:%v", id, d.Round(time.Millisecond))
				needComma = true
			}
			if d := r.DERPLatency[s.STUN6]; d != 0 {
				if needComma {
					buf.WriteByte(',')
				}
				fmt.Fprintf(buf, "%dv6:%v", id, d.Round(time.Millisecond))
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

	// STUN host:port => its best recent latency in last maxAge
	bestRecent := map[string]time.Duration{}

	for t, pr := range c.prev {
		if now.Sub(t) > maxAge {
			delete(c.prev, t)
			continue
		}
		for hp, d := range pr.DERPLatency {
			if bd, ok := bestRecent[hp]; !ok || d < bd {
				bestRecent[hp] = d
			}
		}
	}

	// Then, pick which currently-alive DERP server from the
	// current report has the best latency over the past maxAge.
	var bestAny time.Duration
	for hp := range r.DERPLatency {
		best := bestRecent[hp]
		if r.PreferredDERP == 0 || best < bestAny {
			bestAny = best
			r.PreferredDERP = c.DERP.NodeIDOfSTUNServer(hp)
		}
	}
}

func stringsContains(ss []string, s string) bool {
	for _, v := range ss {
		if s == v {
			return true
		}
	}
	return false
}
