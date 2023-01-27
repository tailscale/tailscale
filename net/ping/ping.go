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
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"tailscale.com/net/netns"
	"tailscale.com/types/logger"
)

type response struct {
	t   time.Time
	err error
}

type outstanding struct {
	ch   chan response
	data []byte
}

// Pinger represents a set of ICMP echo requests to be sent at a single time.
//
// A new instance should be created for each concurrent set of ping requests;
// this type should not be reused.
type Pinger struct {
	c       net.PacketConn
	Logf    logger.Logf
	Verbose bool
	timeNow func() time.Time
	id      uint16 // uint16 per RFC 792
	wg      sync.WaitGroup

	// Following fields protected by mu
	mu    sync.Mutex
	seq   uint16 // uint16 per RFC 792
	pings map[uint16]outstanding
}

// New creates a new Pinger. The Context provided will be used to create
// network listeners, and to set an absolute deadline (if any) on the net.Conn
func New(ctx context.Context, logf logger.Logf) (*Pinger, error) {
	p, err := newUnstarted(ctx, logf)
	if err != nil {
		return nil, err
	}

	// Start by setting the deadline from the context; note that this
	// applies to all future I/O, so we only need to do it once.
	deadline, ok := ctx.Deadline()
	if ok {
		if err := p.c.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
	}

	p.wg.Add(1)
	go p.run(ctx)
	return p, nil
}

func newUnstarted(ctx context.Context, logf logger.Logf) (*Pinger, error) {
	var id [2]byte
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, err
	}

	conn, err := netns.Listener(logf).ListenPacket(ctx, "ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}

	return &Pinger{
		c:       conn,
		Logf:    logf,
		timeNow: time.Now,
		id:      binary.LittleEndian.Uint16(id[:]),
		pings:   make(map[uint16]outstanding),
	}, nil
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
	err := p.c.Close()
	p.wg.Wait()
	return err
}

func (p *Pinger) run(ctx context.Context) {
	defer p.wg.Done()
	buf := make([]byte, 1500)

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
		}

		n, addr, err := p.c.ReadFrom(buf)
		if err != nil {
			// Ignore temporary errors; everything else is fatal
			if netErr, ok := err.(net.Error); !ok || !netErr.Temporary() {
				break
			}
			continue
		}

		p.handleResponse(buf[:n], addr, p.timeNow())
	}

	p.cleanupOutstanding()
}

func (p *Pinger) cleanupOutstanding() {
	// Complete outstanding requests
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, o := range p.pings {
		o.ch <- response{err: net.ErrClosed}
	}
}

func (p *Pinger) handleResponse(buf []byte, addr net.Addr, now time.Time) {
	const ProtocolICMP = 1
	m, err := icmp.ParseMessage(ProtocolICMP, buf)
	if err != nil {
		p.vlogf("handleResponse: invalid packet: %v", err)
		return
	}

	if m.Type != ipv4.ICMPTypeEchoReply {
		p.vlogf("handleResponse: wanted m.Type=%d; got %d", ipv4.ICMPTypeEchoReply, m.Type)
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

	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
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
	n, err := p.c.WriteTo(b, dest)
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
