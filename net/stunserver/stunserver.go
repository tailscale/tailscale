// Copyright (c) Tailscale Inc & AUTHORS
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
	"tailscale.com/net/stun"
)

var (
	stats           = new(metrics.Set)
	stunDisposition = &metrics.LabelMap{Label: "disposition"}
	stunAddrFamily  = &metrics.LabelMap{Label: "family"}
	stunReadError   = stunDisposition.Get("read_error")
	stunNotSTUN     = stunDisposition.Get("not_stun")
	stunWriteError  = stunDisposition.Get("write_error")
	stunSuccess     = stunDisposition.Get("success")

	stunIPv4 = stunAddrFamily.Get("ipv4")
	stunIPv6 = stunAddrFamily.Get("ipv6")
)

func init() {
	stats.Set("counter_requests", stunDisposition)
	stats.Set("counter_addrfamily", stunAddrFamily)
	expvar.Publish("stun", stats)
}

type STUNServer struct {
	ctx context.Context // ctx signals service shutdown
	pc  *net.UDPConn    // pc is the UDP listener
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
	var (
		n   int
		ua  *net.UDPAddr
		err error
	)
	for {
		n, ua, err = s.pc.ReadFromUDP(buf[:])
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
		if ua.IP.To4() != nil {
			stunIPv4.Add(1)
		} else {
			stunIPv6.Add(1)
		}
		addr, _ := netip.AddrFromSlice(ua.IP)
		res := stun.Response(txid, netip.AddrPortFrom(addr, uint16(ua.Port)))
		_, err = s.pc.WriteTo(res, ua)
		if err != nil {
			stunWriteError.Add(1)
		} else {
			stunSuccess.Add(1)
		}
	}
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
