// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stunner

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

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
	Send     func([]byte, net.Addr) (int, error) // sends a packet
	Endpoint func(endpoint string)               // reports an endpoint
	Servers  []string                            // STUN servers to contact
	Resolver *net.Resolver
	Logf     func(format string, args ...interface{})

	sessions map[string]*session
}

type session struct {
	replied chan struct{} // closed when server responds
	tIDs    []stun.TxID   // transaction IDs sent to a server
}

// Receive delivers a STUN packet to the stunner.
func (s *Stunner) Receive(p []byte, fromAddr *net.UDPAddr) {
	if !stun.Is(p) {
		log.Println("stunner: received non-STUN packet")
		return
	}

	responseTID, addr, port, err := stun.ParseResponse(p)
	if err != nil {
		log.Printf("stunner: received bad STUN response: %v", err)
		return
	}

	// Accept any of the tIDs from any of the active sessions.
	for server, session := range s.sessions {
		for _, tID := range session.tIDs {
			if bytes.Equal(tID[:], responseTID[:]) {
				select {
				case <-session.replied:
					return // already got a reply from this server
				default:
				}
				close(session.replied)

				// TODO(crawshaw): use different endpoints returned from
				// different STUN servers to detect NAT types.
				portStr := fmt.Sprintf("%d", port)
				host := net.JoinHostPort(net.IP(addr).String(), portStr)
				if s.Logf != nil {
					s.Logf("STUN server %s reports public endpoint %s", server, host)
				}
				s.Endpoint(host)
				return
			}
		}
	}
	log.Printf("stunner: received STUN packet for unknown transaction: %x", responseTID)
}

// Run starts a Stunner and blocks until all servers either respond
// or are tried multiple times and timeout.
func (s *Stunner) Run(ctx context.Context) error {
	if s.Resolver == nil {
		s.Resolver = net.DefaultResolver
	}
	for _, server := range s.Servers {
		// Generate the transaction IDs for this session.
		tIDs := make([]stun.TxID, len(retryDurations))
		for i := range tIDs {
			if _, err := rand.Read(tIDs[i][:]); err != nil {
				return fmt.Errorf("stunner: rand failed: %v", err)
			}
		}
		if s.sessions == nil {
			s.sessions = make(map[string]*session)
		}
		s.sessions[server] = &session{
			replied: make(chan struct{}),
			tIDs:    tIDs,
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

	for i, d := range retryDurations {
		ctx, cancel := context.WithTimeout(ctx, d)
		err := s.sendSTUN(ctx, session.tIDs[i], server)
		if err != nil {
			if s.Logf != nil {
				s.Logf("stunner: %s: %v", server, err)
			}
		}

		select {
		case <-ctx.Done():
			cancel()
		case <-session.replied:
			cancel()
			if i > 0 && s.Logf != nil {
				s.Logf("stunner: slow STUN response from %s: %d retries", server, i)
			}
			return
		}
	}
	if s.Logf != nil {
		s.Logf("stunner: no STUN response from %s", server)
	}
}

func (s *Stunner) sendSTUN(ctx context.Context, tID stun.TxID, server string) error {
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

	ipAddrs, err := s.Resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("lookup ip addr: %v", err)
	}
	for _, ipAddr := range ipAddrs {
		if ip4 := ipAddr.IP.To4(); ip4 != nil {
			addr.IP = ip4
			addr.Zone = ipAddr.Zone
			break
		}
	}
	if addr.IP == nil {
		return fmt.Errorf("cannot resolve any ipv4 addresses for %s, got: %v", server, ipAddrs)
	}

	req := stun.Request(tID)
	if _, err := s.Send(req, addr); err != nil {
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
