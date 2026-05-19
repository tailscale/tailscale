// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet2

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"tailscale.com/tsnet2/internal/clientsock"
	"tailscale.com/tsnet2/proto"
)

// listener is the [net.Listener] returned by [Server.Listen]. Internally
// it spawns a small pool of accept-worker goroutines that each park a
// "kind=accept" connection on the daemon socket; when the daemon has
// an inbound flow ready, it writes a JSON metadata header on the
// parked conn and then streams cleartext bytes. We hand each such
// conn to Accept callers wrapped in a tsnet2.conn.
type listener struct {
	s       *Server
	network string
	id      string
	addr    addr

	mu     sync.Mutex
	closed bool
	queue  chan net.Conn // accept-ready conns produced by workers
	stopc  chan struct{}
}

var _ net.Listener = (*listener)(nil)

func newListener(s *Server, network, id, addrStr string) *listener {
	return &listener{
		s:       s,
		network: network,
		id:      id,
		addr:    addr{network: network, addr: addrStr},
		queue:   make(chan net.Conn, 4),
		stopc:   make(chan struct{}),
	}
}

// spawnWorkers ensures n accept workers are running. Each worker parks
// a single accept-channel connection on the daemon socket and, when
// the daemon hands it a flow, pushes the resulting conn onto the
// listener's queue and re-spawns to replace itself.
func (ln *listener) spawnWorkers(n int) {
	for i := 0; i < n; i++ {
		go ln.runWorker()
	}
}

// runWorker is one accept-worker iteration: open an accept-channel
// conn, send the header, wait for the daemon to hand back a flow,
// publish it on ln.queue, and then re-spawn.
func (ln *listener) runWorker() {
	for {
		ln.mu.Lock()
		closed := ln.closed
		ln.mu.Unlock()
		if closed {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		c, err := clientsock.Dial(ctx, ln.s.SocketPath, proto.ChannelAccept)
		cancel()
		if err != nil {
			// If we can't reach the daemon, slow down. The listener
			// will exit soon if the server is being closed.
			select {
			case <-ln.stopc:
				return
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}

		// Send the per-listener header line.
		req := struct {
			ListenerID string `json:"listener_id"`
		}{ListenerID: ln.id}
		hdr, _ := json.Marshal(req)
		hdr = append(hdr, '\n')
		if _, err := c.Write(hdr); err != nil {
			c.Close()
			continue
		}

		// Read the accept-header line written by the daemon when it
		// has a flow ready. Then publish the conn (which now carries
		// cleartext bytes) to ln.queue. The reader we created here
		// owns any buffered post-header bytes, so we pass it along
		// to the conn wrapper for first reads.
		br := bufio.NewReader(c)
		line, err := br.ReadBytes('\n')
		if err != nil {
			// Daemon closed without giving us a flow (e.g. listener
			// unregistered or server shutting down). Loop back.
			c.Close()
			select {
			case <-ln.stopc:
				return
			default:
			}
			continue
		}
		var ah proto.AcceptHeader
		if jerr := json.Unmarshal(line[:len(line)-1], &ah); jerr != nil {
			c.Close()
			continue
		}

		// Build the wrapped conn and publish it.
		wrapped := &conn{
			s:      ln.s,
			nc:     c,
			reader: br,
			local:  addr{network: ln.network, addr: ah.Local},
			remote: addr{network: ln.network, addr: ah.Remote},
		}
		select {
		case ln.queue <- wrapped:
		case <-ln.stopc:
			wrapped.Close()
			return
		}
	}
}

// Accept waits for and returns the next connection to the listener.
func (ln *listener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-ln.queue:
		if !ok {
			return nil, fmt.Errorf("tsnet2: %w", net.ErrClosed)
		}
		// Spawn a replacement worker so we keep a parked accept-conn
		// pool ready for the next flow.
		go ln.runWorker()
		return c, nil
	case <-ln.stopc:
		return nil, fmt.Errorf("tsnet2: %w", net.ErrClosed)
	}
}

// Close closes the listener.
func (ln *listener) Close() error {
	ln.mu.Lock()
	if ln.closed {
		ln.mu.Unlock()
		return nil
	}
	ln.closed = true
	close(ln.stopc)
	ln.mu.Unlock()

	// Tell the daemon to unregister the listener.
	if ln.s != nil {
		st := ln.s.stateP
		if st != nil && st.rpc != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = st.rpc.Call(ctx, proto.MethodUnregisterListener, proto.UnregisterListenerParams{ListenerID: ln.id}, nil)
		}
	}
	return nil
}

// Addr returns the listener's network address.
func (ln *listener) Addr() net.Addr { return ln.addr }

// Server returns the tsnet2 Server associated with the listener.
func (ln *listener) Server() *Server { return ln.s }

// addr implements [net.Addr] for tsnet2 listeners and connections.
type addr struct {
	network string
	addr    string
}

func (a addr) Network() string { return a.network }
func (a addr) String() string  { return a.addr }
