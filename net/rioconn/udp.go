// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package rioconn

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tailscale/wireguard-go/conn/winrio"
	"golang.org/x/sys/windows"
)

const (
	// MaxUDPPayloadIPv4 is the maximum UDP payload size over IPv4.
	// IPv4 total length is 65535 bytes, including:
	//   - 20-byte IPv4 header (no options)
	//   - 8-byte UDP header
	MaxUDPPayloadIPv4 = 1<<16 - 1 - 20 - 8
	// MaxUDPPayloadIPv6 is the maximum UDP payload size over IPv6.
	// The IPv6 payload length field excludes the 40-byte base header
	// and includes the 8-byte UDP header.
	MaxUDPPayloadIPv6 = 1<<16 - 1 - 8
	// MaxUDPPayload is the maximum UDP payload size across IP versions.
	MaxUDPPayload = max(MaxUDPPayloadIPv4, MaxUDPPayloadIPv6)
)

// UDPConn implements a UDP socket using the Windows RIO API extensions.
// It supports batched I/O, UDP RSC Offload (URO), and UDP Segmentation
// Offload (USO) to improve performance in high-throughput UDP workloads.
type UDPConn struct {
	config UDPConfig

	*conn // the underlying socket connection with RIO extensions
	udpRx // receiving half-connection
	udpTx // transmitting half-connection
}

// ListenUDP listens for incoming UDP packets on the local address using
// the Registered Input/Output (RIO) API and supports URO and USO when
// available. It returns an error if RIO is not available.
//
// The network must be a UDP network name.
//
// If the IP field of addr is nil or an unspecified IP address,
// ListenUDP listens on all available IP addresses of the local system
// except multicast IP addresses. If the network is "udp" and the local
// IP is unspecified, ListenUDP listens on both IPv4 and IPv6 addresses.
//
// If the Port field of addr is 0, a port number is automatically
// chosen.
//
// The provided options are to configure various aspects of the connection,
// such as RIO buffer sizes, URO and USO parameters and other socket options.
func ListenUDP(network string, addr *net.UDPAddr, options ...UDPOption) (_ *UDPConn, err error) {
	defer func() {
		if err != nil {
			err = &net.OpError{Op: "listen", Net: network, Addr: addr, Err: err}
		}
	}()

	if err := Initialize(); err != nil {
		return nil, err
	}

	udp := &UDPConn{}
	for _, o := range options {
		if o != nil {
			o.applyUDP(&udp.config)
		}
	}

	laddr, dualStack, err := addrPortFromUDPAddr(network, addr)
	if err != nil {
		return nil, err
	}

	// Create the underlying socket with Registered I/O extensions
	// and bind it to the local address.
	udp.conn, err = newConn(windows.SOCK_DGRAM, windows.IPPROTO_UDP,
		dualStack, laddr, &udp.config.Config)
	if err != nil {
		return nil, err
	}
	defer func() {
		// If initialization fails, close the connection to
		// release any allocated resources.
		if err != nil {
			udp.Close()
		}
	}()

	// Initialize the Rx and Tx halves of the connection,
	// which includes allocating memory for RIO buffers
	// and creating RIO completion queues for each half.
	if err := udp.udpRx.init(udp.conn, udp.config); err != nil {
		return nil, fmt.Errorf("failed to initialize Rx: %w", err)
	}
	if err := udp.udpTx.init(udp.conn, udp.config); err != nil {
		return nil, fmt.Errorf("failed to initialize Tx: %w", err)
	}
	// Create the RIO request queue for the connection and associate it
	// with the Rx and Tx completion queues.
	if err := udp.createRequestQueue(
		udp.udpRx.completionQueue(), udp.udpRx.maxOutstandingRequests(),
		udp.udpTx.completionQueue(), udp.udpTx.maxOutstandingRequests(),
	); err != nil {
		return nil, fmt.Errorf("failed to create RIO request queue: %w", err)
	}
	// Disable reporting of ICMP "Port Unreachable" errors as socket errors (golang/go#5834).
	// https://web.archive.org/web/20260208062329/https://support.microsoft.com/en-US/help/263823
	if err := WSAIoctlIn(udp, windows.SIO_UDP_CONNRESET, uint32(0)); err != nil {
		return nil, fmt.Errorf("failed to disable SIO_UDP_CONNRESET: %w", err)
	}
	// Post initial receive requests.
	if err := udp.udpRx.postReceiveRequests(); err != nil {
		return nil, fmt.Errorf("failed to post initial receive requests: %w", err)
	}
	return udp, nil
}

// Config returns the effective configuration of the connection.
// The returned value is immutable for the lifetime of the connection.
func (c *UDPConn) Config() *UDPConfig {
	return &c.config
}

// SetDeadline implements [net.Conn.SetDeadline].
func (c *UDPConn) SetDeadline(t time.Time) error {
	// TODO(nickkhyl): move this and the other deadline methods to the underlying [conn]?
	err1 := c.SetReadDeadline(t)
	err2 := c.SetWriteDeadline(t)
	return errors.Join(err1, err2)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	// TODO(nickkhyl): implement read and write deadlines
	return fmt.Errorf("%w: (%T).SetReadDeadline is not yet implemented", errors.ErrUnsupported, c)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	// TODO(nickkhyl): implement read and write deadlines
	return fmt.Errorf("%w: (%T).SetWriteDeadline is not yet implemented", errors.ErrUnsupported, c)
}

// Close closes the connection, canceling any pending operations,
// and freeing all associated resources.
func (c *UDPConn) Close() error {
	if err := c.conn.Close(); err != nil {
		return err
	}
	// Close the Rx and Tx halves only after closing the underlying connection.
	// This ensures that all in-flight requests complete and that nothing uses
	// the RIO buffers or completion queues after they are closed.
	return errors.Join(c.udpRx.Close(), c.udpTx.Close())
}

// udpNx is a base struct for [udpRx] and [udpTx] half-connections
// that contains common state and logic.
type udpNx struct {
	conn *conn

	// mu protects the fields below and serializes access to the completion queue.
	// Lock order: udpNx.mu > conn.mu.
	mu                sync.Mutex
	requests          *requestRing    // ring of RIO request contexts for this half-connection
	cq                winrio.Cq       // completion queue associated with this half-connection
	hasCompletionsEvt windows.Handle  // signaled by RIO when there are completions to dequeue.
	results           []winrio.Result // dequeued completion results
}

// init initializes the common state for [udpRx] or [udpTx].
// The conn parameter is the underlying connection associated with this half-connection.
// The dataSize parameter specifies the size of the data buffer for each request in the ring,
// and memoryLimit specifies the maximum total memory used by all requests.
func (nx *udpNx) init(conn *conn, dataSize uint16, memoryLimit uintptr) (err error) {
	defer func() {
		if err != nil {
			nx.Close()
		}
	}()
	if nx.requests, err = newRequestRing(dataSize, memoryLimit); err != nil {
		return fmt.Errorf("failed to create request ring: %w", err)
	}
	if nx.hasCompletionsEvt, err = windows.CreateEvent(nil, 0, 0, nil); err != nil {
		return fmt.Errorf("failed to create completion event: %w", err)
	}
	nx.results = make([]winrio.Result, 0, nx.requests.Cap())
	if nx.cq, err = winrio.CreateEventCompletionQueue(nx.requests.Cap(), nx.hasCompletionsEvt, true); err != nil {
		return fmt.Errorf("failed to create completion queue: %w", err)
	}
	nx.conn = conn
	return nil
}

// completionQueue returns the RIO completion queue used by
// the half-connection for completion notifications.
func (nx *udpNx) completionQueue() winrio.Cq {
	return nx.cq
}

// maxOutstandingRequests returns the maximum number of in-flight
// requests the half-connection can post to the RIO request queue
// without blocking.
func (nx *udpNx) maxOutstandingRequests() uint32 {
	return nx.requests.Cap()
}

// Close releases all resources associated with the half-connection.
// It must not be called until the connection using this
// half-connection's buffers and completion queue is closed.
func (nx *udpNx) Close() error {
	nx.mu.Lock()
	defer nx.mu.Unlock()
	if nx.cq != 0 {
		winrio.CloseCompletionQueue(nx.cq)
		nx.cq = 0
	}
	if nx.hasCompletionsEvt != 0 {
		windows.CloseHandle(nx.hasCompletionsEvt)
		nx.hasCompletionsEvt = 0
	}
	if nx.requests != nil {
		if err := nx.requests.Close(); err != nil {
			return err
		}
		nx.requests = nil
	}
	return nil
}
