// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netcheck checks the network conditions from the current host.
package netcheck

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/interfaces"
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

func GetReport(ctx context.Context, logf logger.Logf) (*Report, error) {
	// Mask user context with ours that we guarantee to cancel so
	// we can depend on it being closed in goroutines later.
	// (User ctx might be context.Background, etc)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	closeOnCtx := func(c io.Closer) {
		<-ctx.Done()
		c.Close()
	}

	v6, err := interfaces.HaveIPv6GlobalAddress()
	if err != nil {
		logf("interfaces: %v", err)
	}
	var (
		mu  sync.Mutex
		ret = &Report{
			DERPLatency: map[string]time.Duration{},
		}
		gotIP     = map[string]string{} // server -> IP
		gotIPHair = map[string]string{} // server -> IP for second UDP4 for hairpinning
	)
	add := func(server, ip string, d time.Duration) {
		logf("%s says we are %s (in %v)", server, ip, d)

		mu.Lock()
		defer mu.Unlock()
		ret.UDP = true
		ret.DERPLatency[server] = d
		if strings.Contains(server, "-v6") {
			ret.IPv6 = true
		}
		gotIP[server] = ip

		if ret.PreferredDERP == 0 {
			ret.PreferredDERP = derpIndexOfSTUNHostPort(server)
		}
	}
	addHair := func(server, ip string, d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		gotIPHair[server] = ip
	}

	var pc4, pc6 net.PacketConn

	pc4, err = net.ListenPacket("udp4", ":0")
	if err != nil {
		logf("udp4: %v", err)
		return nil, err
	}
	go closeOnCtx(pc4)

	// And a second UDP4 socket to check hairpinning.
	pc4Hair, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		logf("udp4: %v", err)
		return nil, err
	}
	go closeOnCtx(pc4Hair)

	if v6 {
		pc6, err = net.ListenPacket("udp6", ":0")
		if err != nil {
			logf("udp6: %v", err)
			v6 = false
		} else {
			go closeOnCtx(pc6)
		}
	}

	reader := func(s *stunner.Stunner, pc net.PacketConn, maxReads int) {
		var buf [64 << 10]byte
		for i := 0; i < maxReads; i++ {
			n, addr, err := pc.ReadFrom(buf[:])
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logf("ReadFrom: %v", err)
				return
			}
			ua, ok := addr.(*net.UDPAddr)
			if !ok {
				logf("ReadFrom: unexpected addr %T", addr)
				continue
			}
			s.Receive(buf[:n], ua)
		}

	}

	var grp errgroup.Group

	const unlimited = 9999 // effectively, closed on cancel anyway
	s4 := &stunner.Stunner{
		Send:     pc4.WriteTo,
		Endpoint: add,
		Servers:  []string{"derp1.tailscale.com:3478", "derp2.tailscale.com:3478"},
		Logf:     logf,
	}
	grp.Go(func() error { return s4.Run(ctx) })
	go reader(s4, pc4, unlimited)

	s4Hair := &stunner.Stunner{
		Send:     pc4Hair.WriteTo,
		Endpoint: addHair,
		Servers:  []string{"derp1.tailscale.com:3478", "derp2.tailscale.com:3478"},
		Logf:     logf,
	}
	grp.Go(func() error { return s4Hair.Run(ctx) })
	go reader(s4Hair, pc4Hair, 2)

	if v6 {
		s6 := &stunner.Stunner{
			Endpoint: add,
			Send:     pc6.WriteTo,
			Servers:  []string{"derp1-v6.tailscale.com:3478", "derp2-v6.tailscale.com:3478"},
			Logf:     logf,
			OnlyIPv6: true,
		}
		grp.Go(func() error { return s6.Run(ctx) })
		go reader(s6, pc6, unlimited)
	}

	err = grp.Wait()
	if err != nil {
		return nil, err
	}

	mu.Lock()
	defer mu.Unlock()

	var checkHairpinning bool

	// TODO: generalize this to find at least two out of N DERP
	// servers (where N will be 5+).
	ip1 := gotIP["derp1.tailscale.com:3478"]
	ip2 := gotIP["derp2.tailscale.com:3478"]
	if ip1 != "" && ip2 != "" {
		ret.MappingVariesByDestIP.Set(ip1 != ip2)
		checkHairpinning = ip1 == ip2 && gotIPHair["derp1.tailscale.com:3478"] != ""
	}

	if checkHairpinning {
		hairIPStr, hairPortStr, _ := net.SplitHostPort(gotIPHair["derp1.tailscale.com:3478"])
		hairIP := net.ParseIP(hairIPStr)
		hairPort, _ := strconv.Atoi(hairPortStr)
		if hairIP != nil && hairPort != 0 {
			tx := stun.NewTxID() // random payload
			pc4.WriteTo(tx[:], &net.UDPAddr{IP: hairIP, Port: hairPort})
			var got stun.TxID
			pc4Hair.SetReadDeadline(time.Now().Add(1 * time.Second))
			_, _, err := pc4Hair.ReadFrom(got[:])
			ret.HairPinning.Set(err == nil && got == tx)
		}
	}

	// TODO: if UDP is blocked, try to measure TCP connect times
	// to DERP nodes instead? So UDP-blocked users still get a
	// decent DERP node, rather than being randomly assigned to
	// the other side of the planet? Or try ICMP? (likely also
	// blocked?)

	return ret.Clone(), nil
}

// derpIndexOfSTUNHostPort extracts the derp indes from a STUN host:port like
// "derp1-v6.tailscale.com:3478" or "derp2.tailscale.com:3478".
// It returns 0 on unexpected input.
func derpIndexOfSTUNHostPort(hp string) int {
	hp = strings.TrimSuffix(hp, ".tailscale.com:3478")
	hp = strings.TrimSuffix(hp, "-v6")
	hp = strings.TrimPrefix(hp, "derp")
	n, _ := strconv.Atoi(hp)
	return n // 0 on error is okay
}
