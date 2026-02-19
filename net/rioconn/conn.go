// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"cmp"
	"errors"
	"fmt"
	"iter"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn/winrio"
	"golang.org/x/sys/windows"
)

// conn is a protocol-agnostic base connection with RIO support.
//
// Its exported methods are safe for concurrent use, including
// concurrent calls with each other, with Close, and after Close.
//
// However, the caller must call [conn.acquire] before invoking
// any unexported methods and [conn.release] when done to prevent
// the connection from closing while the operation is in flight.
type conn struct {
	// immutable once [newConn] returns:
	family        int32
	localAddr     net.Addr
	localAddrPort netip.AddrPort
	dualStack     bool
	sotype        int32
	proto         int32
	net           string
	config        *Config

	// guard prevents the connection from closing and its resources from
	// being freed while operations are in flight. All fields below are
	// protected by guard and must not be accessed after the connection
	// is closed and [guard.Acquire] returns false, except by [conn.Close].
	guard     *guard
	closedEvt windows.Handle
	socket    windows.Handle

	// closeMu serializes calls to [conn.Close].
	// Lock order: closeMu > mu.
	closeMu sync.Mutex

	// mu serializes access to the RIO request queue.
	// Lock order: closeMu > mu.
	mu sync.Mutex
	rq winrio.Rq
}

// rawConn implements [syscall.RawConn] for [conn].
type rawConn conn

var (
	_ syscall.Conn    = (*conn)(nil)
	_ syscall.RawConn = (*rawConn)(nil)
)

func newConn(sotype int32, proto int32, dualStack bool, laddr netip.AddrPort, config *Config) (_ *conn, err error) {
	if config == nil {
		config = &Config{}
	}
	sa, family, err := sockaddrFromAddrPort(laddr)
	if err != nil {
		return nil, err
	}
	net, err := networkName(sotype, proto, family, dualStack)
	if err != nil {
		return nil, err
	}
	conn := &conn{
		family:    family,
		dualStack: dualStack,
		sotype:    sotype,
		proto:     proto,
		net:       net,
		config:    config,
		guard:     newGuard(),
	}
	defer func() {
		// If initialization fails, close the connection to release
		// any resources allocated before the error.
		if err != nil {
			conn.Close()
		}
	}()
	// Create a manual-reset event to wake up pending operations on Close.
	if conn.closedEvt, err = windows.CreateEvent(nil, 1, 0, nil); err != nil {
		return nil, fmt.Errorf("failed to create close notification event: %w", err)
	}
	// Create a socket with the WSA_FLAG_REGISTERED_IO flag set.
	if conn.socket, err = rioSocket(family, sotype, proto); err != nil {
		return nil, fmt.Errorf("failed to create socket(%d, %d, %d): %w", family, sotype, proto, err)
	}
	// Enable dual-stack mode by clearing the IPV6_V6ONLY option, if necessary.
	// https://web.archive.org/web/20260208062136/https://learn.microsoft.com/en-us/windows/win32/winsock/dual-stack-sockets
	if dualStack {
		if err := windows.SetsockoptInt(conn.socket, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, 0); err != nil {
			return nil, fmt.Errorf("failed to enable dual-stack mode: %w", err)
		}
	}
	// Invoke caller-provided control functions to set socket options before binding.
	if err := conn.config.Control(net, laddr.String(), (*rawConn)(conn)); err != nil {
		return nil, fmt.Errorf("control failed: %w", err)
	}
	if err := windows.Bind(conn.socket, sa); err != nil {
		return nil, fmt.Errorf("failed to bind socket: %w", err)
	}
	// Record the local address from the actual socket, since the caller
	// may have specified port 0 for automatic assignment.
	if conn.localAddrPort, err = addrPortFromSocket(conn.socket); err != nil {
		return nil, fmt.Errorf("failed to get local address and port: %w", err)
	}
	if conn.localAddr, err = netAddrFromAddrPort(conn.localAddrPort, sotype); err != nil {
		return nil, fmt.Errorf("failed to convert local address and port to net.Addr: %w", err)
	}
	return conn, nil
}

// IsClosed reports whether Close has been called.
func (c *conn) IsClosed() bool {
	return c.guard.IsClosed()
}

// acquire increments the connection's reference count, preventing
// it from closing. If it returns no error, the caller may use the
// connection and must call [conn.release] when done. Otherwise,
// the connection must not be used.
func (c *conn) acquire() error {
	if !c.guard.Acquire() {
		return net.ErrClosed
	}
	return nil
}

// release decrements the connection's reference count.
// Calling release without a matching acquire is a run-time error.
func (c *conn) release() {
	c.guard.Release()
}

// Family returns the socket address family of the connection.
func (c *conn) Family() int32 {
	return c.family
}

// Network returns the network name of the connection.
func (c *conn) Network() string {
	return c.net
}

// IsDualStack reports whether the connection is dual-stack and can send
// and receive packets to and from IPv6 or IPv4-mapped IPv6 addresses.
func (c *conn) IsDualStack() bool {
	return c.dualStack
}

// LocalAddr returns the local network address.
func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

// LocalAddrPort returns the local network address and port.
func (c *conn) LocalAddrPort() netip.AddrPort {
	return c.localAddrPort
}

// SyscallConn returns a raw network connection, or an error if the connection is closed.
func (c *conn) SyscallConn() (syscall.RawConn, error) {
	if c.IsClosed() {
		// Return the error immediately if the connection is already closed.
		// The [conn] implementation handles the case where the connection
		// closes after this call returns, so this is only an optimization.
		return nil, net.ErrClosed
	}
	return c.syscallConn(), nil
}

func (c *conn) syscallConn() syscall.RawConn {
	return (*rawConn)(c)
}

// Control implements [syscall.RawConn.Control].
func (c *rawConn) Control(f func(uintptr)) error {
	return (*conn)(c).rawControl(f)
}

// rawControl implements [rawConn.Control].
func (c *conn) rawControl(f func(uintptr)) error {
	if !c.guard.Acquire() {
		return &net.OpError{Op: "raw-control", Net: c.net, Addr: c.localAddr, Err: net.ErrClosed}
	}
	defer c.guard.Release()
	f(uintptr(c.socket))
	return nil
}

// Read implements [syscall.RawConn.Read].
func (c *rawConn) Read(f func(uintptr) bool) error {
	return &net.OpError{Op: "raw-read", Net: c.net, Source: c.localAddr, Err: errors.ErrUnsupported}
}

// Write implements [syscall.RawConn.Write].
func (c *rawConn) Write(f func(uintptr) bool) error {
	return &net.OpError{Op: "raw-write", Net: c.net, Source: c.localAddr, Err: errors.ErrUnsupported}
}

// createRequestQueue creates a RIO request queue for the connection.
// It must be called before sending or receiving data. The call fails
// if a request queue already exists, if any parameter is invalid,
// or if RIO request queue creation fails.
//
// The caller must ensure that the connection is not closed while
// this call is in progress and that the provided completion queues
// have sufficient capacity for the specified number of outstanding
// requests, plus any requests posted by other connections sharing
// the same completion queues. As of 2026-02-17, completion queues
// are currently not shared between connections.
func (c *conn) createRequestQueue(
	receiveCq winrio.Cq, maxOutstandingReceives uint32,
	sendCq winrio.Cq, maxOutstandingSends uint32,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rq != 0 {
		return errors.New("already created")
	}
	if receiveCq == 0 {
		return errors.New("invalid Rx completion queue")
	}
	if sendCq == 0 {
		return errors.New("invalid Tx completion queue")
	}
	if maxOutstandingReceives == 0 {
		return errors.New("invalid max outstanding receives")
	}
	if maxOutstandingSends == 0 {
		return errors.New("invalid max outstanding sends")
	}
	var err error
	c.rq, err = winrio.CreateRequestQueue(c.socket,
		maxOutstandingReceives, 1,
		maxOutstandingSends, 1,
		receiveCq, sendCq,
		0,
	)
	return err
}

// postReceiveRequests posts multiple receive requests to the RIO request queue.
// It returns an error if posting any request fails.
//
// The caller must ensure that the connection is not closed until this call returns.
func (c *conn) postReceiveRequests(reqs iter.Seq[*request]) (err error) {
	var deferred int
	defer func() {
		// Always commit any deferred receive requests, even if an error occurred.
		if deferred != 0 {
			if commitErr := c.commitReceiveRequests(); commitErr != nil {
				err = errors.Join(err, commitErr)
			}
		}
	}()

	c.mu.Lock()
	defer c.mu.Unlock()
	for req := range reqs {
		if err := c.postReceiveRequestLocked(req, winrio.MsgDefer); err != nil {
			return fmt.Errorf("failed to post receive request #%d: %w", deferred, err)
		}
		deferred++
	}
	return nil
}

// postReceiveRequestLocked posts a single receive request to the
// RIO request queue.
//
// c.mu must be held, and the caller must ensure
// that the connection is not closed until this call returns.
func (c *conn) postReceiveRequestLocked(req *request, flags uint32) error {
	return req.PostReceive(c.rq, flags)
}

// commitReceiveRequests commits previously deferred receive requests.
//
// The caller must ensure that the connection is not closed until
// this call returns. It may be called with or without c.mu held.
func (c *conn) commitReceiveRequests() error {
	// Unlike other ReceiveEx calls, commits do not need to be serialized:
	// https://web.archive.org/web/20260216052922/https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_rioreceiveex
	if err := winrio.ReceiveEx(c.rq, nil, 0, nil, nil, nil, nil, winrio.MsgCommitOnly, 0); err != nil {
		return fmt.Errorf("failed to commit deferred receive requests: %w", err)
	}
	return nil
}

// postSendRequest posts a single send request to the RIO request queue.
// The caller must ensure that the connection is not closed until this call returns.
func (c *conn) postSendRequest(req *request, flags uint32) error {
	// Submit the send request. As the underlying RIO request queue
	// is not thread-safe, we need to serialize access to it.
	c.mu.Lock()
	err := req.PostSend(c.rq, flags)
	c.mu.Unlock()
	return err
}

// commitSendRequests commits previously deferred send requests.
//
// The caller must ensure that the connection is not closed until
// this call returns. It may be called with or without c.mu held.
func (c *conn) commitSendRequests() error {
	// Unlike other SendEx calls, commits do not need to be serialized:
	// https://web.archive.org/web/20260216053051/https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_riosendex
	if err := winrio.SendEx(c.rq, nil, 0, nil, nil, nil, nil, winrio.MsgCommitOnly, 0); err != nil {
		return fmt.Errorf("failed to commit deferred send requests: %w", err)
	}
	return nil
}

// Close closes the connection, cancels any pending operations,
// and releases all associated resources.
// Close is safe for concurrent use.
func (c *conn) Close() error {
	if c == nil {
		return nil
	}

	c.closeMu.Lock()
	defer c.closeMu.Unlock()

	c.guard.Close()       // prevent new operations
	if c.closedEvt != 0 { // wake up blocked operations
		if err := windows.SetEvent(c.closedEvt); err != nil {
			return fmt.Errorf("failed to set close notification event: %w", err)
		}
	}
	c.guard.Wait()
	// At this point, no operations are in flight and no new ones can start,
	// so it is safe to release resources.
	if c.socket != 0 {
		windows.Closesocket(c.socket)
		c.socket = 0
	}
	if c.closedEvt != 0 {
		windows.CloseHandle(c.closedEvt)
		c.closedEvt = 0
	}
	return nil
}

func rioSocket(family, sotype, proto int32) (windows.Handle, error) {
	const rioWSAFlags = windows.WSA_FLAG_REGISTERED_IO |
		windows.WSA_FLAG_NO_HANDLE_INHERIT |
		windows.WSA_FLAG_OVERLAPPED
	return windows.WSASocket(family, sotype, proto, nil, 0, rioWSAFlags)
}

// WSAIoctlIn issues an ioctl command with the provided code and input value
// on the connection's underlying socket. It is a type-safe shorthand for calling
// [syscall.RawConn.Control] with a function that invokes [windows.WSAIoctl]
// with the appropriate arguments, without any output buffer.
func WSAIoctlIn[Input any](conn syscall.Conn, code uint32, in Input) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	controlErr := rawConn.Control(func(s uintptr) {
		ret := uint32(0)
		err = windows.WSAIoctl(windows.Handle(s), code,
			(*byte)(unsafe.Pointer(&in)), uint32(unsafe.Sizeof(in)),
			nil, 0, &ret, nil, 0,
		)
	})
	return cmp.Or(controlErr, err)
}
