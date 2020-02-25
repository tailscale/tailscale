// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netcheck checks the network conditions from the current host.
package netcheck

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"tailscale.com/interfaces"
	"tailscale.com/stunner"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
)

type Report struct {
	UDP                   bool                     // UDP works
	IPv6                  bool                     // IPv6 works
	MappingVariesByDestIP opt.Bool                 // for IPv4
	DERPLatency           map[string]time.Duration // keyed by STUN host:port
}

func GetReport(ctx context.Context, logf logger.Logf) (*Report, error) {
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
		gotIP = map[string]string{} // server -> IP
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
	}

	var pc4, pc6 net.PacketConn

	pc4, err = net.ListenPacket("udp4", ":0")
	if err != nil {
		logf("udp4: %v", err)
		return nil, err
	}
	go closeOnCtx(pc4)
	if v6 {
		pc6, err = net.ListenPacket("udp6", ":0")
		if err != nil {
			logf("udp6: %v", err)
			v6 = false
		} else {
			go closeOnCtx(pc6)
		}
	}

	reader := func(s *stunner.Stunner, pc net.PacketConn) {
		var buf [64 << 10]byte
		for {
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
			logf("Packet from %v: %q", ua, buf[:n])
			s.Receive(buf[:n], ua)
		}

	}

	var grp errgroup.Group
	s4 := &stunner.Stunner{
		Send:     pc4.WriteTo,
		Endpoint: add,
		Servers:  []string{"derp1.tailscale.com:3478", "derp2.tailscale.com:3478"},
		Logf:     logf,
	}
	grp.Go(func() error { return s4.Run(ctx) })
	go reader(s4, pc4)

	if v6 {
		s6 := &stunner.Stunner{
			Endpoint: add,
			Send:     pc6.WriteTo,
			Servers:  []string{"derp1-v6.tailscale.com:3478", "derp2-v6.tailscale.com:3478"},
			Logf:     logf,
			OnlyIPv6: true,
		}
		grp.Go(func() error { return s6.Run(ctx) })
		go reader(s6, pc6)
	}

	err = grp.Wait()
	logf("stunner.Run: %v", err)

	mu.Lock()
	defer mu.Unlock() // unnecessary, but feels weird without

	// TODO: generalize this to find at least two out of N DERP
	// servers (where N will be 5+).
	ip1 := gotIP["derp1.tailscale.com:3478"]
	ip2 := gotIP["derp2.tailscale.com:3478"]
	if ip1 != "" && ip2 != "" {
		ret.MappingVariesByDestIP.Set(ip1 != ip2)
	}

	return ret, nil
}
