// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stunner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/net/dnscache"
	"tailscale.com/stun"
	"tailscale.com/types/structs"
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

	// onPacket is the internal version of Endpoint that does de-dup.
	// It's set by Run.
	onPacket func(server, endpoint string, d time.Duration)

	Servers []string // STUN servers to contact

	// DNSCache optionally specifies a DNSCache to use.
	// If nil, a DNS cache is not used.
	DNSCache *dnscache.Resolver

	// Logf optionally specifies a log function. If nil, logging is disabled.
	Logf func(format string, args ...interface{})

	// OnlyIPv6 controls whether IPv6 is exclusively used.
	// If false, only IPv4 is used. There is currently no mixed mode.
	OnlyIPv6 bool

	// MaxTries optionally provides a mapping from server name to the maximum
	// number of tries that should be made for a given server.
	// If nil or a server is not present in the map, the default is 1.
	// Values less than 1 are ignored.
	MaxTries map[string]int

	mu       sync.Mutex
	inFlight map[stun.TxID]request
}

func (s *Stunner) addTX(tx stun.TxID, server string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.inFlight[tx]; dup {
		panic("unexpected duplicate STUN TransactionID")
	}
	s.inFlight[tx] = request{sent: time.Now(), server: server}
}

func (s *Stunner) removeTX(tx stun.TxID) (request, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight == nil {
		return request{}, false
	}
	r, ok := s.inFlight[tx]
	if ok {
		delete(s.inFlight, tx)
	} else {
		s.logf("stunner: got STUN packet for unknown TxID %x", tx)
	}
	return r, ok
}

type request struct {
	_      structs.Incomparable
	sent   time.Time
	server string
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
		if _, err := stun.ParseBindingRequest(p); err == nil {
			// This was probably our own netcheck hairpin
			// check probe coming in late. Ignore.
			return
		}
		s.logf("stunner: received unexpected STUN message response from %v: %v", fromAddr, err)
		return
	}
	r, ok := s.removeTX(tx)
	if !ok {
		return
	}
	d := now.Sub(r.sent)

	host := net.JoinHostPort(net.IP(addr).String(), fmt.Sprint(port))
	s.onPacket(r.server, host, d)
}

func (s *Stunner) resolver() *net.Resolver {
	return net.DefaultResolver
}

// cleanUpPostRun zeros out some fields, mostly for debugging (so
// things crash or race+fail if there's a sender still running.)
func (s *Stunner) cleanUpPostRun() {
	s.mu.Lock()
	s.inFlight = nil
	s.mu.Unlock()
}

// Run starts a Stunner and blocks until all servers either respond
// or are tried multiple times and timeout.
// It can not be called concurrently with itself.
func (s *Stunner) Run(ctx context.Context) error {
	for _, server := range s.Servers {
		if _, _, err := net.SplitHostPort(server); err != nil {
			return fmt.Errorf("Stunner.Run: invalid server %q (in Server list %q)", server, s.Servers)
		}
	}
	if len(s.Servers) == 0 {
		return errors.New("stunner: no Servers")
	}

	s.inFlight = make(map[stun.TxID]request)
	defer s.cleanUpPostRun()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type sender struct {
		ctx    context.Context
		cancel context.CancelFunc
	}
	var (
		needMu  sync.Mutex
		need    = make(map[string]sender) // keyed by server; deleted when done
		allDone = make(chan struct{})     // closed when need is empty
	)
	s.onPacket = func(server, endpoint string, d time.Duration) {
		needMu.Lock()
		defer needMu.Unlock()
		sender, ok := need[server]
		if !ok {
			return
		}
		sender.cancel()
		delete(need, server)
		s.Endpoint(server, endpoint, d)
		if len(need) == 0 {
			close(allDone)
		}
	}

	var wg sync.WaitGroup
	for _, server := range s.Servers {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		need[server] = sender{ctx, cancel}
	}
	needMu.Lock()
	for server, sender := range need {
		wg.Add(1)
		server, ctx := server, sender.ctx
		go func() {
			defer wg.Done()
			s.sendPackets(ctx, server)
		}()
	}
	needMu.Unlock()
	var err error
	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-allDone:
		cancel()
	}
	wg.Wait()

	var missing []string
	needMu.Lock()
	for server := range need {
		missing = append(missing, server)
	}
	needMu.Unlock()

	if len(missing) == 0 || err == nil {
		return nil
	}
	return fmt.Errorf("got STUN error: %w; missing replies from: %v", err, strings.Join(missing, ", "))
}

func (s *Stunner) serverAddr(ctx context.Context, server string) (*net.UDPAddr, error) {
	hostStr, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return nil, err
	}
	addrPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("port: %v", err)
	}
	if addrPort == 0 {
		addrPort = 3478
	}
	addr := &net.UDPAddr{Port: addrPort}

	var ipAddrs []net.IPAddr
	if s.DNSCache != nil {
		ip, err := s.DNSCache.LookupIP(ctx, hostStr)
		if err != nil {
			return nil, err
		}
		ipAddrs = []net.IPAddr{{IP: ip}}
	} else {
		ipAddrs, err = s.resolver().LookupIPAddr(ctx, hostStr)
		if err != nil {
			return nil, fmt.Errorf("lookup ip addr (%q): %v", hostStr, err)
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
			return nil, fmt.Errorf("cannot resolve any ipv6 addresses for %s, got: %v", server, ipAddrs)
		}
		return nil, fmt.Errorf("cannot resolve any ipv4 addresses for %s, got: %v", server, ipAddrs)
	}
	return addr, nil
}

// maxTriesForServer returns the maximum number of STUN queries that
// will be sent to server (for one call to Run). The default is 1.
func (s *Stunner) maxTriesForServer(server string) int {
	if v, ok := s.MaxTries[server]; ok && v > 0 {
		return v
	}
	return 1
}

func (s *Stunner) sendPackets(ctx context.Context, server string) error {
	addr, err := s.serverAddr(ctx, server)
	if err != nil {
		return err
	}
	maxTries := s.maxTriesForServer(server)
	for i := 0; i < maxTries; i++ {
		txID := stun.NewTxID()
		req := stun.Request(txID)
		s.addTX(txID, server)
		_, err = s.Send(req, addr)
		if err != nil {
			return fmt.Errorf("send: %v", err)
		}

		select {
		case <-ctx.Done():
			// Ignore error. The caller deals with handling contexts.
			// We only use it to dermine when to stop spraying STUN packets.
			return nil
		case <-time.After(time.Millisecond * time.Duration(50+rand.Intn(200))):
		}
	}
	return nil
}
