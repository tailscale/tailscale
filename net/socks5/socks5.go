// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package socks5 is a SOCKS5 server implementation.
//
// This is used for userspace networking in Tailscale. Specifically,
// this is used for dialing out of the machine to other nodes, without
// the host kernel's involvement, so it doesn't proper routing tables,
// TUN, IPv6, etc. This package is meant to only handle the SOCKS5 protocol
// details and not any integration with Tailscale internals itself.
//
// The glue between this package and Tailscale is in net/socks5/tssocks.
package socks5

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"time"

	"tailscale.com/types/logger"
)

// Authentication METHODs described in RFC 1928, section 3.
const (
	noAuthRequired   byte = 0
	passwordAuth     byte = 2
	noAcceptableAuth byte = 255
)

// passwordAuthVersion is the auth version byte described in RFC 1929.
const passwordAuthVersion = 1

// socks5Version is the byte that represents the SOCKS version
// in requests.
const socks5Version byte = 5

// commandType are the bytes sent in SOCKS5 packets
// that represent the kind of connection the client needs.
type commandType byte

// The set of valid SOCKS5 commands as described in RFC 1928.
const (
	connect      commandType = 1
	bind         commandType = 2
	udpAssociate commandType = 3
)

// addrType are the bytes sent in SOCKS5 packets
// that represent particular address types.
type addrType byte

// The set of valid SOCKS5 address types as defined in RFC 1928.
const (
	ipv4       addrType = 1
	domainName addrType = 3
	ipv6        addrType = 4
)

// replyCode are the bytes sent in SOCKS5 packets
// that represent replies from the server to a client request.
type replyCode byte

// The set of valid SOCKS5 reply types as per RFC 1928.
const (
	success              replyCode = 0
	generalFailure       replyCode = 1
	connectionNotAllowed replyCode = 2
	networkUnreachable   replyCode = 3
	hostUnreachable      replyCode = 4
	connectionRefused    replyCode = 5
	ttlExpired           replyCode = 6
	commandNotSupported  replyCode = 7
	addrTypeNotSupported replyCode = 8
)

// UDP conn default buffer size and read timeout.
const (
	bufferSize  = 8 * 1024
	readTimeout = 5 * time.Second
)

// Server is a SOCKS5 proxy server.
type Server struct {
	// Logf optionally specifies the logger to use.
	// If nil, the standard logger is used.
	Logf logger.Logf

	// Dialer optionally specifies the dialer to use for outgoing connections.
	// If nil, the net package's standard dialer is used.
	Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

	// Username and Password, if set, are the credential clients must provide.
	Username string
	Password string
}

func (s *Server) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := s.Dialer
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	return dial(ctx, network, addr)
}

func (s *Server) logf(format string, args ...any) {
	logf := s.Logf
	if logf == nil {
		logf = log.Printf
	}
	logf(format, args...)
}

// Serve accepts and handles incoming connections on the given listener.
func (s *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			conn := &Conn{logf: s.logf, clientConn: c, srv: s}
			err := conn.Run()
			if err != nil {
				s.logf("client connection failed: %v", err)
			}
		}()
	}
}

// Conn is a SOCKS5 connection for client to reach
// server.
type Conn struct {
	// The struct is filled by each of the internal
	// methods in turn as the transaction progresses.

	logf       logger.Logf
	srv        *Server
	clientConn net.Conn
	request    *request

	udpClientAddr  net.Addr
	udpTargetConns map[socksAddr]net.Conn
}

// Run starts the new connection.
func (c *Conn) Run() error {
	needAuth := c.srv.Username != "" || c.srv.Password != ""
	authMethod := noAuthRequired
	if needAuth {
		authMethod = passwordAuth
	}

	err := parseClientGreeting(c.clientConn, authMethod)
	if err != nil {
		c.clientConn.Write([]byte{socks5Version, noAcceptableAuth})
		return err
	}
	c.clientConn.Write([]byte{socks5Version, authMethod})
	if !needAuth {
		return c.handleRequest()
	}

	user, pwd, err := parseClientAuth(c.clientConn)
	userMatch := subtle.ConstantTimeCompare([]byte(user), []byte(c.srv.Username))
	pwdMatch := subtle.ConstantTimeCompare([]byte(pwd), []byte(c.srv.Password))
	if err != nil || userMatch != 1 || pwdMatch != 1 {
		c.clientConn.Write([]byte{1, 1})
		return err
	}
	c.clientConn.Write([]byte{1, 0})

	return c.handleRequest()
}

func (c *Conn) handleRequest() error {
	req, err := parseClientRequest(c.clientConn)
	if err != nil {
		res := errorResponse(generalFailure)
		buf, _ := res.marshal()
		c.clientConn.Write(buf)
		return err
	}

	c.request = req
	switch req.command {
	case connect:
		return c.handleTCP()
	case udpAssociate:
		return c.handleUDP()
	default:
		res := errorResponse(commandNotSupported)
		buf, _ := res.marshal()
		c.clientConn.Write(buf)
		return fmt.Errorf("unsupported command %v", req.command)
	}
}
