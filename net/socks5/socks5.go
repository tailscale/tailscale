// Copyright (c) Tailscale Inc & AUTHORS
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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	ipv6       addrType = 4
)

// replyCode are the bytes sent in SOCKS5 packets
// that represent replies from the server to a client
// request.
type replyCode byte

// The set of valid SOCKS5 reply types as per the RFC 1928.
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
func (s *Server) Serve(l net.Listener) error {
	defer l.Close()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			conn := &Conn{logf: s.Logf, clientConn: c, srv: s}
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

	udpClientAddr net.Addr
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
	if err != nil || user != c.srv.Username || pwd != c.srv.Password {
		c.clientConn.Write([]byte{1, 1}) // auth error
		return err
	}
	c.clientConn.Write([]byte{1, 0}) // auth success

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

func (c *Conn) handleTCP() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv, err := c.srv.dial(
		ctx,
		"tcp",
		c.request.destination.hostPort(),
	)
	if err != nil {
		res := errorResponse(generalFailure)
		buf, _ := res.marshal()
		c.clientConn.Write(buf)
		return err
	}
	defer srv.Close()

	localAddr := srv.LocalAddr().String()
	serverAddr, serverPort, err := splitHostPort(localAddr)
	if err != nil {
		return err
	}

	res := &response{
		reply: success,
		bindAddr: socksAddr{
			addrType: getAddrType(serverAddr),
			addr:     serverAddr,
			port:     serverPort,
		},
	}
	buf, err := res.marshal()
	if err != nil {
		res = errorResponse(generalFailure)
		buf, _ = res.marshal()
	}
	c.clientConn.Write(buf)

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(c.clientConn, srv)
		if err != nil {
			err = fmt.Errorf("from backend to client: %w", err)
		}
		errc <- err
	}()
	go func() {
		_, err := io.Copy(srv, c.clientConn)
		if err != nil {
			err = fmt.Errorf("from client to backend: %w", err)
		}
		errc <- err
	}()
	return <-errc
}

func (c *Conn) handleUDP() error {
	// The DST.ADDR and DST.PORT fields contain the address and port that
	// the client expects to use to send UDP datagrams on for the
	// association. The server MAY use this information to limit access
	// to the association.
	// @see Page 6, https://datatracker.ietf.org/doc/html/rfc1928.
	//
	// We do NOT limit the access from the client currently in this implementation.
	_ = c.request.destination

	addr := c.clientConn.LocalAddr()
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return err
	}
	clientUDPConn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		res := errorResponse(generalFailure)
		buf, _ := res.marshal()
		c.clientConn.Write(buf)
		return err
	}
	defer clientUDPConn.Close()

	serverUDPConn, err := net.ListenPacket("udp", "[::]:0")
	if err != nil {
		res := errorResponse(generalFailure)
		buf, _ := res.marshal()
		c.clientConn.Write(buf)
		return err
	}
	defer serverUDPConn.Close()

	bindAddr, bindPort, err := splitHostPort(clientUDPConn.LocalAddr().String())
	if err != nil {
		return err
	}

	res := &response{
		reply: success,
		bindAddr: socksAddr{
			addrType: getAddrType(bindAddr),
			addr:     bindAddr,
			port:     bindPort,
		},
	}
	buf, err := res.marshal()
	if err != nil {
		res = errorResponse(generalFailure)
		buf, _ = res.marshal()
	}
	c.clientConn.Write(buf)

	return c.transferUDP(c.clientConn, clientUDPConn, serverUDPConn)
}

func (c *Conn) transferUDP(associatedTCP net.Conn, clientConn net.PacketConn, targetConn net.PacketConn) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const bufferSize = 8 * 1024
	const readTimeout = 5 * time.Second

	// client -> target
	go func() {
		defer cancel()
		buf := make([]byte, bufferSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				err := c.handleUDPRequest(clientConn, targetConn, buf, readTimeout)
				if err != nil {
					if isTimeout(err) {
						continue
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					c.logf("udp transfer: handle udp request fail: %v", err)
				}
			}
		}
	}()

	// target -> client
	go func() {
		defer cancel()
		buf := make([]byte, bufferSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				err := c.handleUDPResponse(targetConn, clientConn, buf, readTimeout)
				if err != nil {
					if isTimeout(err) {
						continue
					}
					if errors.Is(err, net.ErrClosed) {
						return
					}
					c.logf("udp transfer: handle udp response fail: %v", err)
				}
			}
		}
	}()

	// A UDP association terminates when the TCP connection that the UDP
	// ASSOCIATE request arrived on terminates. RFC1928
	_, err := io.Copy(io.Discard, associatedTCP)
	if err != nil {
		err = fmt.Errorf("udp associated tcp conn: %w", err)
	}
	return err
}

func (c *Conn) handleUDPRequest(
	clientConn net.PacketConn,
	targetConn net.PacketConn,
	buf []byte,
	readTimeout time.Duration,
) error {
	// add a deadline for the read to avoid blocking forever
	_ = clientConn.SetReadDeadline(time.Now().Add(readTimeout))
	n, addr, err := clientConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("read from client: %w", err)
	}
	c.udpClientAddr = addr
	req, data, err := parseUDPRequest(buf[:n])
	if err != nil {
		return fmt.Errorf("parse udp request: %w", err)
	}
	targetAddr, err := net.ResolveUDPAddr("udp", req.addr.hostPort())
	if err != nil {
		c.logf("resolve target addr fail: %v", err)
	}

	nn, err := targetConn.WriteTo(data, targetAddr)
	if err != nil {
		return fmt.Errorf("write to target %s fail: %w", targetAddr, err)
	}
	if nn != len(data) {
		return fmt.Errorf("write to target %s fail: %w", targetAddr, io.ErrShortWrite)
	}
	return nil
}

func (c *Conn) handleUDPResponse(
	targetConn net.PacketConn,
	clientConn net.PacketConn,
	buf []byte,
	readTimeout time.Duration,
) error {
	// add a deadline for the read to avoid blocking forever
	_ = targetConn.SetReadDeadline(time.Now().Add(readTimeout))
	n, addr, err := targetConn.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("read from target: %w", err)
	}
	host, port, err := splitHostPort(addr.String())
	if err != nil {
		return fmt.Errorf("split host port: %w", err)
	}
	hdr := udpRequest{addr: socksAddr{addrType: getAddrType(host), addr: host, port: port}}
	pkt, err := hdr.marshal()
	if err != nil {
		return fmt.Errorf("marshal udp request: %w", err)
	}
	data := append(pkt, buf[:n]...)
	// use addr from client to send back
	nn, err := clientConn.WriteTo(data, c.udpClientAddr)
	if err != nil {
		return fmt.Errorf("write to client: %w", err)
	}
	if nn != len(data) {
		return fmt.Errorf("write to client: %w", io.ErrShortWrite)
	}
	return nil
}

func isTimeout(err error) bool {
	terr, ok := errors.Unwrap(err).(interface{ Timeout() bool })
	return ok && terr.Timeout()
}

func splitHostPort(hostport string) (host string, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err
	}
	portInt, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	if portInt < 0 || portInt > 65535 {
		return "", 0, fmt.Errorf("invalid port number %d", portInt)
	}
	return host, uint16(portInt), nil
}

// parseClientGreeting parses a request initiation packet.
func parseClientGreeting(r io.Reader, authMethod byte) error {
	var hdr [2]byte
	_, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return fmt.Errorf("could not read packet header")
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("incompatible SOCKS version")
	}
	count := int(hdr[1])
	methods := make([]byte, count)
	_, err = io.ReadFull(r, methods)
	if err != nil {
		return fmt.Errorf("could not read methods")
	}
	for _, m := range methods {
		if m == authMethod {
			return nil
		}
	}
	return fmt.Errorf("no acceptable auth methods")
}

func parseClientAuth(r io.Reader) (usr, pwd string, err error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", "", fmt.Errorf("could not read auth packet header")
	}
	if hdr[0] != passwordAuthVersion {
		return "", "", fmt.Errorf("bad SOCKS auth version")
	}
	usrLen := int(hdr[1])
	usrBytes := make([]byte, usrLen)
	if _, err := io.ReadFull(r, usrBytes); err != nil {
		return "", "", fmt.Errorf("could not read auth packet username")
	}
	var hdrPwd [1]byte
	if _, err := io.ReadFull(r, hdrPwd[:]); err != nil {
		return "", "", fmt.Errorf("could not read auth packet password length")
	}
	pwdLen := int(hdrPwd[0])
	pwdBytes := make([]byte, pwdLen)
	if _, err := io.ReadFull(r, pwdBytes); err != nil {
		return "", "", fmt.Errorf("could not read auth packet password")
	}
	return string(usrBytes), string(pwdBytes), nil
}

func getAddrType(addr string) addrType {
	if ip := net.ParseIP(addr); ip != nil {
		if ip.To4() != nil {
			return ipv4
		}
		return ipv6
	}
	return domainName
}

// request represents data contained within a SOCKS5
// connection request packet.
type request struct {
	command     commandType
	destination socksAddr
}

// parseClientRequest converts raw packet bytes into a
// SOCKS5Request struct.
func parseClientRequest(r io.Reader) (*request, error) {
	var hdr [3]byte
	_, err := io.ReadFull(r, hdr[:])
	if err != nil {
		return nil, fmt.Errorf("could not read packet header")
	}
	cmd := hdr[1]

	destination, err := parseSocksAddr(r)
	return &request{
		command:     commandType(cmd),
		destination: destination,
	}, err
}

type socksAddr struct {
	addrType addrType
	addr     string
	port     uint16
}

var zeroSocksAddr = socksAddr{addrType: ipv4, addr: "0.0.0.0", port: 0}

func parseSocksAddr(r io.Reader) (addr socksAddr, err error) {
	var addrTypeData [1]byte
	_, err = io.ReadFull(r, addrTypeData[:])
	if err != nil {
		return socksAddr{}, fmt.Errorf("could not read address type")
	}

	dstAddrType := addrType(addrTypeData[0])
	var destination string
	switch dstAddrType {
	case ipv4:
		var ip [4]byte
		_, err = io.ReadFull(r, ip[:])
		if err != nil {
			return socksAddr{}, fmt.Errorf("could not read IPv4 address")
		}
		destination = net.IP(ip[:]).String()
	case domainName:
		var dstSizeByte [1]byte
		_, err = io.ReadFull(r, dstSizeByte[:])
		if err != nil {
			return socksAddr{}, fmt.Errorf("could not read domain name size")
		}
		dstSize := int(dstSizeByte[0])
		domainName := make([]byte, dstSize)
		_, err = io.ReadFull(r, domainName)
		if err != nil {
			return socksAddr{}, fmt.Errorf("could not read domain name")
		}
		destination = string(domainName)
	case ipv6:
		var ip [16]byte
		_, err = io.ReadFull(r, ip[:])
		if err != nil {
			return socksAddr{}, fmt.Errorf("could not read IPv6 address")
		}
		destination = net.IP(ip[:]).String()
	default:
		return socksAddr{}, fmt.Errorf("unsupported address type")
	}
	var portBytes [2]byte
	_, err = io.ReadFull(r, portBytes[:])
	if err != nil {
		return socksAddr{}, fmt.Errorf("could not read port")
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	return socksAddr{
		addrType: dstAddrType,
		addr:     destination,
		port:     port,
	}, nil
}

func (s socksAddr) marshal() ([]byte, error) {
	var addr []byte
	switch s.addrType {
	case ipv4:
		addr = net.ParseIP(s.addr).To4()
		if addr == nil {
			return nil, fmt.Errorf("invalid IPv4 address for binding")
		}
	case domainName:
		if len(s.addr) > 255 {
			return nil, fmt.Errorf("invalid domain name for binding")
		}
		addr = make([]byte, 0, len(s.addr)+1)
		addr = append(addr, byte(len(s.addr)))
		addr = append(addr, []byte(s.addr)...)
	case ipv6:
		addr = net.ParseIP(s.addr).To16()
		if addr == nil {
			return nil, fmt.Errorf("invalid IPv6 address for binding")
		}
	default:
		return nil, fmt.Errorf("unsupported address type")
	}

	pkt := []byte{byte(s.addrType)}
	pkt = append(pkt, addr...)
	pkt = binary.BigEndian.AppendUint16(pkt, s.port)
	return pkt, nil
}
func (s socksAddr) hostPort() string {
	return net.JoinHostPort(s.addr, strconv.Itoa(int(s.port)))
}

// response contains the contents of
// a response packet sent from the proxy
// to the client.
type response struct {
	reply    replyCode
	bindAddr socksAddr
}

func errorResponse(code replyCode) *response {
	return &response{reply: code, bindAddr: zeroSocksAddr}
}

// marshal converts a SOCKS5Response struct into
// a packet. If res.reply == Success, it may throw an error on
// receiving an invalid bind address. Otherwise, it will not throw.
func (res *response) marshal() ([]byte, error) {
	pkt := make([]byte, 3)
	pkt[0] = socks5Version
	pkt[1] = byte(res.reply)
	pkt[2] = 0 // null reserved byte

	addrPkt, err := res.bindAddr.marshal()
	if err != nil {
		return nil, err
	}

	return append(pkt, addrPkt...), nil
}

type udpRequest struct {
	frag byte
	addr socksAddr
}

// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
func parseUDPRequest(data []byte) (*udpRequest, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("invalid packet length")
	}

	// reserved bytes
	if !(data[0] == 0 && data[1] == 0) {
		return nil, nil, fmt.Errorf("invalid udp request header")
	}

	frag := data[2]

	reader := bytes.NewReader(data[3:])
	addr, err := parseSocksAddr(reader)
	bodyLen := reader.Len() // (*bytes.Reader).Len() return unread data length
	body := data[len(data)-bodyLen:]
	return &udpRequest{
		frag: frag,
		addr: addr,
	}, body, err
}

func (u *udpRequest) marshal() ([]byte, error) {
	pkt := make([]byte, 3)
	pkt[0] = 0
	pkt[1] = 0
	pkt[2] = u.frag

	addrPkt, err := u.addr.marshal()
	if err != nil {
		return nil, err
	}

	return append(pkt, addrPkt...), nil
}
