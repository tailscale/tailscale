// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stunner

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"tailscale.com/net/dnscache"
	"tailscale.com/stun"
)

// Stunner sends a STUN request to several servers and handles a response.
//
// It is designed to used on a connection owned by other code and so does
// not directly reference a net.Conn of any sort. Instead, the user should
// provide Send function to send packets, and call Receive when a new
// STUN response is received.
//
// In response, a Stunner will call Endpoint with any endpoints determined
// for the connection. (An endpoint may be reported multiple times if
// multiple servers are provided.)
type Stunner struct {
	// Send sends a packet.
	// It will typically be a PacketConn.WriteTo method value.
	Send func([]byte, net.Addr) (int, error) // sends a packet

	// Endpoint is called whenever a STUN response is received.
	// The server is the STUN server that replied, endpoint is the ip:port
	// from the STUN response, and d is the duration that the STUN request
	// took on the wire (not including DNS lookup time.
	Endpoint func(server, endpoint string, d time.Duration)

	Servers []string // STUN servers to contact

	// DNSCache optionally specifies a DNSCache to use.
	// If nil, a DNS cache is not used.
	DNSCache *dnscache.Resolver

	// Logf optionally specifies a log function. If nil, logging is disabled.
	Logf func(format string, args ...interface{})

	// OnlyIPv6 controls whether IPv6 is exclusively used.
	// If false, only IPv4 is used. There is currently no mixed mode.
	OnlyIPv6 bool

	// sessions tracks the state of each server.
	// It's keyed by the STUN server (from the Servers field).
	sessions map[string]*session

	mu       sync.Mutex
	inFlight map[stun.TxID]request
}

func (s *Stunner) addTX(tx stun.TxID, server string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight == nil {
		s.inFlight = make(map[stun.TxID]request)
	}
	s.inFlight[tx] = request{sent: time.Now(), server: server}
}

func (s *Stunner) removeTX(tx stun.TxID) (request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.inFlight[tx]
	delete(s.inFlight, tx)
	return r, ok
}

type request struct {
	sent   time.Time
	server string
}

type session struct {
	ctx    context.Context // closed via call to done when reply received
	cancel context.CancelFunc
}

func (s *Stunner) logf(format string, args ...interface{}) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Receive delivers a STUN packet to the stunner.
func (s *Stunner) Receive(p []byte, fromAddr *net.UDPAddr) {
	if !stun.Is(p) {
		s.logf("[unexpected] stunner: received non-STUN packet")
		return
	}
	now := time.Now()
	tx, addr, port, err := stun.ParseResponse(p)
	if err != nil {
		s.logf("stunner: received bad STUN response: %v", err)
		return
	}
	r, ok := s.removeTX(tx)
	if !ok {
		s.logf("stunner: got STUN packet for unknown TxID %x", tx)
		return
	}
	d := now.Sub(r.sent)

	session := s.sessions[r.server]
	if session != nil {
		host := net.JoinHostPort(net.IP(addr).String(), fmt.Sprint(port))
		s.Endpoint(r.server, host, d)
		session.cancel()
	}
}

func (s *Stunner) resolver() *net.Resolver {
	return net.DefaultResolver
}

// Run starts a Stunner and blocks until all servers either respond
// or are tried multiple times and timeout.
//
// TODO: this always returns success now. It should return errors
// if certain servers are unavailable probably. Or if all are.
// Or some configured threshold are.
func (s *Stunner) Run(ctx context.Context) error {
	s.sessions = map[string]*session{}
	for _, server := range s.Servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return fmt.Errorf("Stunner.Run: invalid server %q (in Server list %q)", server, s.Servers)
		}
		sctx, cancel := context.WithCancel(ctx)
		s.sessions[server] = &session{
			ctx:    sctx,
			cancel: cancel,
		}
	}
	// after this point, the s.sessions map is read-only

	var wg sync.WaitGroup
	for _, server := range s.Servers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			s.runServer(ctx, server)
		}(server)
	}
	wg.Wait()

	return nil
}

func (s *Stunner) runServer(ctx context.Context, server string) {
	session := s.sessions[server]

	// If we're using a DNS cache, prime the cache before doing
	// any quick timeouts (100ms, etc) so the timeout doesn't
	// apply to the first DNS lookup.
	if s.DNSCache != nil {
		_, _ = s.DNSCache.LookupIP(ctx, server)
	}

	for i, d := range retryDurations {
		ctx, cancel := context.WithTimeout(ctx, d)
		err := s.sendSTUN(ctx, server)
		if err != nil {
			s.logf("stunner: sendSTUN(%q): %v", server, err)
		}

		select {
		case <-ctx.Done():
			cancel()
		case <-session.ctx.Done():
			cancel()
			if i > 0 {
				s.logf("stunner: slow STUN response from %s: %d retries", server, i)
			}
			return
		}
	}
	s.logf("stunner: no STUN response from %s", server)
}

func (s *Stunner) sendSTUN(ctx context.Context, server string) error {
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		return err
	}
	addrPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("port: %v", err)
	}
	if addrPort == 0 {
		addrPort = 3478
	}
	addr := &net.UDPAddr{Port: addrPort}

	var ipAddrs []net.IPAddr
	if s.DNSCache != nil {
		ip, err := s.DNSCache.LookupIP(ctx, host)
		if err != nil {
			return fmt.Errorf("lookup ip addr from cache (%q): %v", host, err)
		}
		ipAddrs = []net.IPAddr{{IP: ip}}
	} else {
		ipAddrs, err = s.resolver().LookupIPAddr(ctx, host)
		if err != nil {
			return fmt.Errorf("lookup ip addr (%q): %v", host, err)
		}
	}
	for _, ipAddr := range ipAddrs {
		ip4 := ipAddr.IP.To4()
		if ip4 != nil {
			if s.OnlyIPv6 {
				continue
			}
			addr.IP = ip4
			break
		} else if s.OnlyIPv6 {
			addr.IP = ipAddr.IP
			addr.Zone = ipAddr.Zone
		}
	}
	if addr.IP == nil {
		if s.OnlyIPv6 {
			return fmt.Errorf("cannot resolve any ipv6 addresses for %s, got: %v", server, ipAddrs)
		}
		return fmt.Errorf("cannot resolve any ipv4 addresses for %s, got: %v", server, ipAddrs)
	}

	txID := stun.NewTxID()
	req := stun.Request(txID)
	s.addTX(txID, server)
	_, err = s.Send(req, addr)
	if err != nil {
		return fmt.Errorf("send: %v", err)
	}
	return nil
}

var retryDurations = []time.Duration{
	100 * time.Millisecond,
	100 * time.Millisecond,
	100 * time.Millisecond,
	200 * time.Millisecond,
	200 * time.Millisecond,
	400 * time.Millisecond,
	800 * time.Millisecond,
	1600 * time.Millisecond,
	3200 * time.Millisecond,
}
