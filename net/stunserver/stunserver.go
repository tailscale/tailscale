// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package stunserver implements a STUN server. The package publishes a number of stats
// to expvar under the top level label "stun". Logs are sent to the standard log package.
package stunserver

import (
	"context"
	"errors"
	"expvar"
	"io"
	"log"
	"net"
	"net/netip"
	"time"

	"tailscale.com/metrics"
	"tailscale.com/net/pktinfo"
	"tailscale.com/net/stun"
)

var (
	stats           = metrics.NewSet("stun")
	stunDisposition = stats.NewLabelMap("counter_requests", "disposition")
	stunAddrFamily  = stats.NewLabelMap("counter_addrfamily", "family")
	stunReadError   = stunDisposition.Get("read_error")
	stunNotSTUN     = stunDisposition.Get("not_stun")
	stunWriteError  = stunDisposition.Get("write_error")
	stunSuccess     = stunDisposition.Get("success")

	stunIPv4 = stunAddrFamily.Get("ipv4")
	stunIPv6 = stunAddrFamily.Get("ipv6")

	// stunNoLocalAddr counts requests for which the kernel didn't report
	// the local address the request was sent to, despite pktinfo being
	// enabled, so the response was sent from a kernel-chosen source
	// address instead.
	stunNoLocalAddr = newCounter("counter_no_local_addr")
)

func newCounter(name string) *expvar.Int {
	v := new(expvar.Int)
	stats.Set(name, v)
	return v
}

type STUNServer struct {
	ctx context.Context // ctx signals service shutdown
	pc  *net.UDPConn    // pc is the UDP listener

	// pktInfo is whether the kernel reports the destination address of
	// each request (see [pktinfo.Enable]). When it does, the response is
	// sent from that same address rather than from whatever source
	// address a route lookup on the reply's destination would pick.
	// On a multi-homed server those differ, and replies from the wrong
	// address break conntrack-based policy routing (tailscale/tailscale#21404).
	pktInfo bool
}

// New creates a new STUN server. The server is shutdown when ctx is done.
func New(ctx context.Context) *STUNServer {
	return &STUNServer{ctx: ctx}
}

// Listen binds the listen socket for the server at listenAddr.
func (s *STUNServer) Listen(listenAddr string) error {
	uaddr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	s.pc, err = net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	if err := pktinfo.Enable(s.pc); err == nil {
		s.pktInfo = true
	} else if !errors.Is(err, errors.ErrUnsupported) {
		log.Printf("STUN server: pktinfo unavailable; responses will use the kernel-chosen source address: %v", err)
	}
	log.Printf("STUN server listening on %v", s.LocalAddr())
	// close the listener on shutdown in order to break out of the read loop
	go func() {
		<-s.ctx.Done()
		s.pc.Close()
	}()
	return nil
}

// Serve starts serving responses to STUN requests. Listen must be called before Serve.
func (s *STUNServer) Serve() error {
	var buf [64 << 10]byte
	var oob, oobOut [256]byte
	for {
		n, remote, local, err := s.readFrom(buf[:], oob[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("STUN ReadFrom: %v", err)
			time.Sleep(time.Second)
			stunReadError.Add(1)
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			stunNotSTUN.Add(1)
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			stunNotSTUN.Add(1)
			continue
		}
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		if remote.Addr().Is4() {
			stunIPv4.Add(1)
		} else {
			stunIPv6.Add(1)
		}
		if s.pktInfo && !local.IsValid() {
			stunNoLocalAddr.Add(1)
		}
		res := stun.Response(txid, remote)
		if err := s.writeTo(res, remote, local, oobOut[:0]); err != nil {
			stunWriteError.Add(1)
		} else {
			stunSuccess.Add(1)
		}
	}
}

// readFrom reads one datagram into buf, returning its length, its sender,
// and the local address it was sent to (the zero [netip.Addr] if unknown).
// oob is scratch space for control messages.
func (s *STUNServer) readFrom(buf, oob []byte) (n int, remote netip.AddrPort, local netip.Addr, err error) {
	if !s.pktInfo {
		n, remote, err = s.pc.ReadFromUDPAddrPort(buf)
		return n, remote, netip.Addr{}, err
	}
	n, oobn, _, remote, err := s.pc.ReadMsgUDPAddrPort(buf, oob)
	if err != nil {
		return 0, remote, netip.Addr{}, err
	}
	return n, remote, pktinfo.Dst(oob[:oobn]), nil
}

// writeTo sends b to remote from the local address local, if known.
// Otherwise the kernel picks the source address. oob is scratch space for
// control messages.
func (s *STUNServer) writeTo(b []byte, remote netip.AddrPort, local netip.Addr, oob []byte) error {
	oob = pktinfo.AppendSrc(oob, local)
	if len(oob) == 0 {
		_, err := s.pc.WriteToUDPAddrPort(b, remote)
		return err
	}
	_, _, err := s.pc.WriteMsgUDPAddrPort(b, oob, remote)
	return err
}

// ListenAndServe starts the STUN server on listenAddr.
func (s *STUNServer) ListenAndServe(listenAddr string) error {
	if err := s.Listen(listenAddr); err != nil {
		return err
	}
	return s.Serve()
}

// LocalAddr returns the local address of the STUN server. It must not be called before ListenAndServe.
func (s *STUNServer) LocalAddr() net.Addr {
	return s.pc.LocalAddr()
}
