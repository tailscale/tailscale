// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package ping allows sending ICMP echo requests to a host in order to
// determine network latency.
package ping

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
	"tailscale.com/util/multierr"
)

const (
	v4Type = "ip4:icmp"
	v6Type = "ip6:icmp"
)

type response struct {
	t   time.Time
	err error
}

type outstanding struct {
	ch   chan response
	data []byte
}

// PacketListener defines the interface required to listen to packages
// on an address.
type ListenPacketer interface {
	ListenPacket(ctx context.Context, typ string, addr string) (net.PacketConn, error)
}

// Pinger represents a set of ICMP echo requests to be sent at a single time.
//
// A new instance should be created for each concurrent set of ping requests;
// this type should not be reused.
type Pinger struct {
	lp ListenPacketer

	// closed guards against send incrementing the waitgroup concurrently with close.
	closed  atomic.Bool
	Logf    logger.Logf
	Verbose bool
	timeNow func() time.Time
	id      uint16 // uint16 per RFC 792
	wg      sync.WaitGroup

	// Following fields protected by mu
	mu sync.Mutex
	// conns is a map of "type" to net.PacketConn, type is either
	// "ip4:icmp" or "ip6:icmp"
	conns map[string]net.PacketConn
	seq   uint16 // uint16 per RFC 792
	pings map[uint16]outstanding
}

// New creates a new Pinger. The Context provided will be used to create
// network listeners, and to set an absolute deadline (if any) on the net.Conn
func New(ctx context.Context, logf logger.Logf, lp ListenPacketer) *Pinger {
	var id [2]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		panic("net/ping: New:" + err.Error())
	}

	return &Pinger{
		lp:      lp,
		Logf:    logf,
		timeNow: time.Now,
		id:      binary.LittleEndian.Uint16(id[:]),
		pings:   make(map[uint16]outstanding),
	}
}

func (p *Pinger) mkconn(ctx context.Context, typ, addr string) (net.PacketConn, error) {
	if p.closed.Load() {
		return nil, net.ErrClosed
	}

	c, err := p.lp.ListenPacket(ctx, typ, addr)
	if err != nil {
		return nil, err
	}

	// Start by setting the deadline from the context; note that this
	// applies to all future I/O, so we only need to do it once.
	deadline, ok := ctx.Deadline()
	if ok {
		if err := c.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
	}

	p.wg.Add(1)
	go p.run(ctx, c, typ)

	return c, err
}

// getConn creates or returns a conn matching typ which is ip4:icmp
// or ip6:icmp.
func (p *Pinger) getConn(ctx context.Context, typ string) (net.PacketConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.conns[typ]; ok {
		return c, nil
	}

	var addr = "0.0.0.0"
	if typ == v6Type {
		addr = "::"
	}
	c, err := p.mkconn(ctx, typ, addr)
	if err != nil {
		return nil, err
	}
	mak.Set(&p.conns, typ, c)
	return c, nil
}

func (p *Pinger) logf(format string, a ...any) {
	if p.Logf != nil {
		p.Logf(format, a...)
	} else {
		log.Printf(format, a...)
	}
}

func (p *Pinger) vlogf(format string, a ...any) {
	if p.Verbose {
		p.logf(format, a...)
	}
}

func (p *Pinger) Close() error {
	p.closed.Store(true)

	p.mu.Lock()
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()

	var errors []error
	for _, c := range conns {
		if err := c.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	p.wg.Wait()
	p.cleanupOutstanding()

	return multierr.New(errors...)
}

func (p *Pinger) run(ctx context.Context, conn net.PacketConn, typ string) {
	defer p.wg.Done()
	defer func() {
		conn.Close()
		p.mu.Lock()
		delete(p.conns, typ)
		p.mu.Unlock()
	}()
	buf := make([]byte, 1500)

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
		}

		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			// Ignore temporary errors; everything else is fatal
			if netErr, ok := err.(net.Error); !ok || !netErr.Temporary() {
				break
			}
			continue
		}

		p.handleResponse(buf[:n], p.timeNow(), typ)
	}
}

func (p *Pinger) cleanupOutstanding() {
	// Complete outstanding requests
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, o := range p.pings {
		o.ch <- response{err: net.ErrClosed}
	}
}

func (p *Pinger) handleResponse(buf []byte, now time.Time, typ string) {
	// We need to handle responding to both IPv4
	// and IPv6.
	var icmpType icmp.Type
	switch typ {
	case v4Type:
		icmpType = ipv4.ICMPTypeEchoReply
	case v6Type:
		icmpType = ipv6.ICMPTypeEchoReply
	default:
		p.vlogf("handleResponse: unknown icmp.Type")
		return
	}

	m, err := icmp.ParseMessage(icmpType.Protocol(), buf)
	if err != nil {
		p.vlogf("handleResponse: invalid packet: %v", err)
		return
	}

	if m.Type != icmpType {
		p.vlogf("handleResponse: wanted m.Type=%d; got %d", icmpType, m.Type)
		return
	}

	resp, ok := m.Body.(*icmp.Echo)
	if !ok || resp == nil {
		p.vlogf("handleResponse: wanted body=*icmp.Echo; got %v", m.Body)
		return
	}

	// We assume we sent this if the ID in the response is ours.
	if uint16(resp.ID) != p.id {
		p.vlogf("handleResponse: wanted ID=%d; got %d", p.id, resp.ID)
		return
	}

	// Search for existing running echo request
	var o outstanding
	p.mu.Lock()
	if o, ok = p.pings[uint16(resp.Seq)]; ok {
		// Ensure that the data matches before we delete from our map,
		// so a future correct packet will be handled correctly.
		if bytes.Equal(resp.Data, o.data) {
			delete(p.pings, uint16(resp.Seq))
		} else {
			p.vlogf("handleResponse: got response for Seq %d with mismatched data", resp.Seq)
			ok = false
		}
	} else {
		p.vlogf("handleResponse: got response for unknown Seq %d", resp.Seq)
	}
	p.mu.Unlock()

	if ok {
		o.ch <- response{t: now}
	}
}

// Send sends an ICMP Echo Request packet to the destination, waits for a
// response, and returns the duration between when the request was sent and
// when the reply was received.
//
// If provided, "data" is sent with the packet and is compared upon receiving a
// reply.
func (p *Pinger) Send(ctx context.Context, dest net.Addr, data []byte) (time.Duration, error) {
	// Use sequential sequence numbers on the assumption that we will not
	// wrap around when using a single Pinger instance
	p.mu.Lock()
	p.seq++
	seq := p.seq
	p.mu.Unlock()

	// Check whether the address is IPv4 or IPv6 to
	// determine the icmp.Type and conn to use.
	var conn net.PacketConn
	var icmpType icmp.Type = ipv4.ICMPTypeEcho
	ap, err := netip.ParseAddr(dest.String())
	if err != nil {
		return 0, err
	}
	if ap.Is6() {
		icmpType = ipv6.ICMPTypeEchoRequest
		conn, err = p.getConn(ctx, v6Type)
	} else {
		conn, err = p.getConn(ctx, v4Type)
	}
	if err != nil {
		return 0, err
	}

	m := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(p.id),
			Seq:  int(seq),
			Data: data,
		},
	}
	b, err := m.Marshal(nil)
	if err != nil {
		return 0, err
	}

	// Register our response before sending since we could otherwise race a
	// quick reply.
	ch := make(chan response, 1)
	p.mu.Lock()
	p.pings[seq] = outstanding{ch: ch, data: data}
	p.mu.Unlock()

	start := p.timeNow()
	n, err := conn.WriteTo(b, dest)
	if err != nil {
		return 0, err
	} else if n != len(b) {
		return 0, fmt.Errorf("conn.WriteTo: got %v; want %v", n, len(b))
	}

	select {
	case resp := <-ch:
		if resp.err != nil {
			return 0, resp.err
		}
		return resp.t.Sub(start), nil

	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
