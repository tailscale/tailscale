// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"

	"tailscale.com/tsnet2/proto"
	"tailscale.com/tsnet2/traffic"
)

// serveDatapath handles a client-initiated outbound dial. The client
// writes a one-line JSON DatapathHeader; the daemon dials via the
// hosted tsnet.Server, writes a JSON status line, then splices bytes
// both directions.
func (d *Daemon) serveDatapath(c net.Conn) {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := br.ReadBytes('\n')
	if err != nil {
		d.logf("daemon: datapath header read: %v", err)
		return
	}
	c.SetReadDeadline(time.Time{})

	var hdr proto.DatapathHeader
	if err := json.Unmarshal(line[:len(line)-1], &hdr); err != nil {
		d.logf("daemon: datapath header parse: %v", err)
		return
	}
	switch hdr.Op {
	case "dial":
		d.handleDial(c, br, hdr)
	default:
		d.logf("daemon: unknown datapath op %q", hdr.Op)
	}
}

func (d *Daemon) handleDial(appConn net.Conn, br *bufio.Reader, hdr proto.DatapathHeader) {
	ts, err := d.tsServer()
	if err != nil {
		d.logf("daemon: dial before start: %v", err)
		_ = writeDialReply(appConn, err)
		return
	}
	ctx, cancel := context.WithTimeout(d.shutdownCtx, 30*time.Second)
	defer cancel()
	netConn, err := ts.Dial(ctx, hdr.Network, hdr.Addr)
	if err != nil {
		_ = writeDialReply(appConn, err)
		return
	}
	if err := writeDialReply(appConn, nil); err != nil {
		netConn.Close()
		return
	}

	connID := newID()
	local := netConn.LocalAddr().String()
	remote := netConn.RemoteAddr().String()
	var whois map[string]any
	if ap, ok := parseAddrPort(remote); ok {
		whois = d.whoIs(d.shutdownCtx, ap)
	}
	d.traffic.Open(connID, traffic.DirOut, "tcp", local, remote, "", map[string]any{
		"whois": whois,
	})
	spliceCommon(d.traffic, connID, appConn, br, netConn)
}

// writeDialReply emits a single \n-terminated JSON status line so the
// client knows whether the dial succeeded before bytes start flowing.
func writeDialReply(c net.Conn, err error) error {
	reply := struct {
		OK  bool   `json:"ok"`
		Err string `json:"err,omitempty"`
	}{OK: err == nil}
	if err != nil {
		reply.Err = err.Error()
	}
	b, _ := json.Marshal(reply)
	b = append(b, '\n')
	_, werr := c.Write(b)
	return werr
}

// serveAccept services a parked accept-worker connection. The client
// writes one line {"listener_id":"..."} and parks. When the daemon's
// netstack has an inbound flow for that listener, deliverInbound
// signals the slot with the netConn and metadata; serveAccept then
// writes the AcceptHeader on the parked conn and splices bytes.
func (d *Daemon) serveAccept(c net.Conn) {
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := br.ReadBytes('\n')
	if err != nil {
		d.logf("daemon: accept header read: %v", err)
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	var req struct {
		ListenerID string `json:"listener_id"`
	}
	if err := json.Unmarshal(line[:len(line)-1], &req); err != nil {
		d.logf("daemon: accept header parse: %v", err)
		c.Close()
		return
	}
	if req.ListenerID == "" {
		d.logf("daemon: accept header missing listener_id")
		c.Close()
		return
	}

	slot := d.pushAcceptSlot(req.ListenerID, c)
	var res acceptResult
	select {
	case res = <-slot.done:
	case <-d.shutdownCtx.Done():
		d.removeAcceptSlot(req.ListenerID, slot)
		c.Close()
		return
	}
	if res.err != nil {
		d.logf("daemon: accept slot err: %v", res.err)
		c.Close()
		return
	}

	hdrBytes, _ := json.Marshal(res.hdr)
	hdrBytes = append(hdrBytes, '\n')
	if _, err := c.Write(hdrBytes); err != nil {
		d.logf("daemon: accept hdr write: %v", err)
		c.Close()
		if res.c != nil {
			res.c.Close()
		}
		return
	}

	spliceCommon(d.traffic, res.connID, c, br, res.c)
}

// spliceCommon bidirectionally copies bytes between appConn and
// netConn, tee-ing each direction into the traffic logger. The conn
// id is provided by the caller so it matches the "open" record
// already written. Closes both conns on exit and emits the "close"
// record.
func spliceCommon(log *traffic.Logger, connID string, appConn net.Conn, appReader *bufio.Reader, netConn net.Conn) {
	start := time.Now()
	appToPeer := traffic.NewFlowSink(log, connID, traffic.DirAppPeer)
	peerToApp := traffic.NewFlowSink(log, connID, traffic.DirPeerApp)
	var wg sync.WaitGroup
	var cerr atomicErr

	// appConn (with any pre-read buffered bytes) -> netConn
	wg.Add(1)
	go func() {
		defer wg.Done()
		var r io.Reader = appConn
		if appReader != nil && appReader.Buffered() > 0 {
			r = io.MultiReader(appReader, appConn)
		} else if appReader != nil {
			r = appReader
		}
		_, err := copyWithTee(netConn, r, appToPeer)
		cerr.Set(err)
		if cw, ok := netConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = netConn.Close()
		}
	}()
	// netConn -> appConn
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := copyWithTee(appConn, netConn, peerToApp)
		cerr.Set(err)
		if cw, ok := appConn.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = appConn.Close()
		}
	}()
	wg.Wait()
	appConn.Close()
	netConn.Close()
	errStr := ""
	if err := cerr.Get(); err != nil && err != io.EOF {
		errStr = err.Error()
	}
	// bytes_in: peer -> app (what the peer sent us)
	// bytes_out: app -> peer (what we sent out)
	log.Close_(connID, peerToApp.Total(), appToPeer.Total(), time.Since(start), errStr)
}

// closeWriter is implemented by net.TCPConn, *gonet.TCPConn, and
// *net.UnixConn — all the conn types we splice. We use CloseWrite to
// half-close so the other direction can drain.
type closeWriter interface {
	CloseWrite() error
}

// copyWithTee copies src->dst while feeding each chunk into sink.
func copyWithTee(dst io.Writer, src io.Reader, sink *traffic.FlowSink) (int64, error) {
	var total int64
	buf := make([]byte, 32*1024)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			sink.Add(buf[:n])
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

// atomicErr captures the first non-nil error from either copy
// direction, in a mutex-protected manner.
type atomicErr struct {
	mu  sync.Mutex
	err error
}

func (a *atomicErr) Set(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	if a.err == nil {
		a.err = err
	}
	a.mu.Unlock()
}
func (a *atomicErr) Get() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

