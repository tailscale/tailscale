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

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
	var oob [4096]byte
	var (
		n, oobn int
		remote  netip.AddrPort
		local   net.IP
		err     error
		cm4     ipv4.ControlMessage
		cm6     ipv6.ControlMessage
	)
	for {
		n, oobn, _, remote, err = s.pc.ReadMsgUDPAddrPort(buf[:], oob[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("STUN ReadFrom: %v", err)
			time.Sleep(time.Second)
			stunReadError.Add(1)
			continue
		}

		if remote.Addr().Is4() {
			err = cm4.Parse(oob[:oobn])
		} else {
			err = cm6.Parse(oob[:oobn])
		}
		if err != nil {
			log.Printf("parse control msg error: %v", err)
			continue
		}
		if remote.Addr().Is4() {
			local = cm4.Dst
		} else {
			local = cm6.Dst
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
		if remote.Addr().Is4() {
			stunIPv4.Add(1)
		} else {
			stunIPv6.Add(1)
		}
		res := stun.Response(txid, remote)

		// TODO(raggi): send upstream patch to provide a way to serialize a
		// control message into an existng buffer.
		if remote.Addr().Is4() {
			cm4 = ipv4.ControlMessage{
				Src: local,
			}
			oobn = copy(oob[:], cm4.Marshal())
		} else {
			cm6 = ipv6.ControlMessage{
				Src: local,
			}
			oobn = copy(oob[:], cm6.Marshal())
		}
		_, _, err = s.pc.WriteMsgUDPAddrPort(res, oob[:oobn], remote)
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
