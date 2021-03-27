// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ipnlocal

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"html"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"

	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
	"tailscale.com/tailcfg"
)

var initListenConfig func(*net.ListenConfig, netaddr.IP, *interfaces.State, string) error

func peerAPIListen(ip netaddr.IP, ifState *interfaces.State, tunIfName string) (ln net.Listener, err error) {
	ipStr := ip.String()

	var lc net.ListenConfig
	if initListenConfig != nil {
		// On iOS/macOS, this sets the lc.Control hook to
		// setsockopt the interface index to bind to, to get
		// out of the network sandbox.
		if err := initListenConfig(&lc, ip, ifState, tunIfName); err != nil {
			return nil, err
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
			ipStr = ""
		}
	}

	tcp4or6 := "tcp4"
	if ip.Is6() {
		tcp4or6 = "tcp6"
	}

	// Make a best effort to pick a deterministic port number for
	// the ip The lower three bytes are the same for IPv4 and IPv6
	// Tailscale addresses (at least currently), so we'll usually
	// get the same port number on both address families for
	// dev/debugging purposes, which is nice. But it's not so
	// deterministic that people will bake this into clients.
	// We try a few times just in case something's already
	// listening on that port (on all interfaces, probably).
	for try := uint8(0); try < 5; try++ {
		a16 := ip.As16()
		hashData := a16[len(a16)-3:]
		hashData[0] += try
		tryPort := (32 << 10) | uint16(crc32.ChecksumIEEE(hashData))
		ln, err = lc.Listen(context.Background(), tcp4or6, net.JoinHostPort(ipStr, strconv.Itoa(int(tryPort))))
		if err == nil {
			return ln, nil
		}
	}
	// Fall back to random ephemeral port.
	return lc.Listen(context.Background(), tcp4or6, net.JoinHostPort(ipStr, "0"))
}

type peerAPIListener struct {
	ln       net.Listener
	lb       *LocalBackend
	urlStr   string
	selfNode *tailcfg.Node
}

func (pln *peerAPIListener) Port() int {
	ta, ok := pln.ln.Addr().(*net.TCPAddr)
	if !ok {
		return 0
	}
	return ta.Port
}

func (pln *peerAPIListener) serve() {
	defer pln.ln.Close()
	logf := pln.lb.logf
	for {
		c, err := pln.ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			logf("peerapi.Accept: %v", err)
			return
		}
		ta, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			c.Close()
			logf("peerapi: unexpected RemoteAddr %#v", c.RemoteAddr())
			continue
		}
		ipp, ok := netaddr.FromStdAddr(ta.IP, ta.Port, "")
		if !ok {
			logf("peerapi: bogus TCPAddr %#v", ta)
			c.Close()
			continue
		}
		peerNode, peerUser, ok := pln.lb.WhoIs(ipp)
		if !ok {
			logf("peerapi: unknown peer %v", ipp)
			c.Close()
			continue
		}
		h := &peerAPIHandler{
			isSelf:     pln.selfNode.User == peerNode.User,
			remoteAddr: ipp,
			peerNode:   peerNode,
			peerUser:   peerUser,
			lb:         pln.lb,
		}
		httpServer := &http.Server{
			Handler: h,
		}
		go httpServer.Serve(&oneConnListener{Listener: pln.ln, conn: c})
	}
}

type oneConnListener struct {
	net.Listener
	conn net.Conn
}

func (l *oneConnListener) Accept() (c net.Conn, err error) {
	c = l.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	l.conn = nil
	return
}

func (l *oneConnListener) Close() error { return nil }

// peerAPIHandler serves the Peer API for a source specific client.
type peerAPIHandler struct {
	remoteAddr netaddr.IPPort
	isSelf     bool                // whether peerNode is owned by same user as this node
	peerNode   *tailcfg.Node       // peerNode is who's making the request
	peerUser   tailcfg.UserProfile // profile of peerNode
	lb         *LocalBackend
}

func (h *peerAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	who := h.peerUser.DisplayName
	fmt.Fprintf(w, `<html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<body>
<h1>Hello, %s (%v)</h1>
This is my Tailscale device. Your device is %v.
`, html.EscapeString(who), h.remoteAddr.IP, html.EscapeString(h.peerNode.ComputedName))

	if h.isSelf {
		fmt.Fprintf(w, "<p>You are the owner of this node.\n")
	}
}
