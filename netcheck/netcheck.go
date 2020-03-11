// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netcheck checks the network conditions from the current host.
package netcheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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

	GetSTUNConn4 func() STUNConn
	GetSTUNConn6 func() STUNConn

	s4          *stunner.Stunner
	s6          *stunner.Stunner
	hairTX      stun.TxID
	gotHairSTUN chan *net.UDPAddr
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
	var st *stunner.Stunner
	if src == nil || src.IP == nil {
		panic("bogus src")
	}
	if c.handleHairSTUN(pkt, src) {
		return
	}
	if src.IP.To4() != nil {
		st = c.s4
	} else {
		st = c.s6
	}
	if st != nil {
		st.Receive(pkt, src)
	}
}

// GetReport gets a report.
//
// It may not be called concurrently with itself.
func (c *Client) GetReport(ctx context.Context) (*Report, error) {
	// Mask user context with ours that we guarantee to cancel so
	// we can depend on it being closed in goroutines later.
	// (User ctx might be context.Background, etc)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		c.s4 = nil
		c.s6 = nil
	}()
	c.hairTX = stun.NewTxID() // random payload
	c.gotHairSTUN = make(chan *net.UDPAddr, 1)

	if c.DERP == nil {
		return nil, errors.New("netcheck: GetReport: Client.DERP is nil")
	}
	stuns4 := c.DERP.STUN4()
	stuns6 := c.DERP.STUN6()
	if len(stuns4) == 0 {
		// TODO: make this work? if we ever need it
		// to. Requirement for self-hosted Tailscale might be
		// to run a DERP+STUN server co-resident with the
		// Control server.
		return nil, errors.New("netcheck: GetReport: no STUN servers, no Report")
	}
	for _, s := range stuns4 {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return nil, fmt.Errorf("netcheck: GetReport: bogus STUN4 server %q", s)
		}
	}
	for _, s := range stuns6 {
		if _, _, err := net.SplitHostPort(s); err != nil {
			return nil, fmt.Errorf("netcheck: GetReport: bogus STUN6 server %q", s)
		}
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
			pc4Hair.WriteTo(stun.Request(c.hairTX), dst)
			time.AfterFunc(500*time.Millisecond, func() { hairTimeout <- true })
		}
	}

	var (
		mu  sync.Mutex
		ret = &Report{
			DERPLatency: map[string]time.Duration{},
		}
		gotEP           = map[string]string{} // server -> ipPort
		gotEP4          string
		bestDerpLatency time.Duration
	)
	add := func(server, ipPort string, d time.Duration) {
		c.logf("%s says we are %s (in %v)", server, ipPort, d)

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

		if ret.PreferredDERP == 0 || d < bestDerpLatency {
			bestDerpLatency = d
			ret.PreferredDERP = c.DERP.NodeIDOfSTUNServer(server)
		}
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
	}
	c.s4 = s4
	grp.Go(func() error {
		err := s4.Run(ctx)
		if err == nil {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		// If we got at least one IPv4 endpoint, treat that as
		// good enough.
		if gotEP4 != "" {
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
		}
		c.s6 = s6
		grp.Go(func() error {
			if err := s6.Run(ctx); err != nil {
				// IPv6 seemed like it was configured, but actually failed.
				// Just log and return a nil error.
				c.logf("netcheck: ignoring IPv6 failure: %v", err)
			}
			return nil
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
		case <-c.gotHairSTUN:
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

	return ret.Clone(), nil
}
