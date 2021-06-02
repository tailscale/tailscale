package uring

// #cgo LDFLAGS: -luring
// #include "io_uring.c"
import "C"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/device"
	"inet.af/netaddr"
)

// A UDPConn is a recv-only UDP fd manager.
// TODO: Support writes.
// TODO: support multiplexing multiple fds?
// May be more expensive than having multiple urings, and certainly more complicated.
// TODO: API review for performance.
// We'd like to enqueue a bunch of recv calls and deqeueue them later,
// but we have a problem with buffer management: We get our buffers just-in-time
// from wireguard-go, which means we have to make copies.
// That's OK for now, but later it could be a performance issue.
// For now, keep it simple and enqueue/dequeue in a single step.
// TODO: IPv6
type UDPConn struct {
	ptr   *C.go_uring
	close sync.Once
	conn  *net.UDPConn
	file  *os.File // must keep file from being GC'd
	fd    C.int
	local net.Addr
	reqs  [8]req
}

func NewUDPConn(conn *net.UDPConn) (*UDPConn, error) {
	// this is dumb
	local := conn.LocalAddr().String()
	ip, err := netaddr.ParseIPPort(local)
	if err != nil {
		return nil, fmt.Errorf("failed to parse UDPConn local addr %s as IP: %w", local, err)
	}
	if !ip.IP().Is4() {
		return nil, fmt.Errorf("uring only supports udp4 (for now), got local addr %s", local)
	}
	// TODO: probe for system capabilities: https://unixism.net/loti/tutorial/probe_liburing.html
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	r := new(C.go_uring)

	const queue_depth = 16 // TODO: What value to use here?
	C.io_uring_queue_init(queue_depth, r, 0)
	u := &UDPConn{
		ptr:   r,
		conn:  conn,
		file:  file,
		fd:    C.int(file.Fd()),
		local: conn.LocalAddr(),
	}
	for i := range u.reqs {
		if err := u.submitRequest(i); err != nil {
			u.Close() // TODO: will this crash?
			return nil, err
		}
	}
	return u, nil
}

type req struct {
	mhdr C.go_msghdr
	iov  C.go_iovec
	sa   C.go_sockaddr_in
	buf  [device.MaxSegmentSize]byte
}

func (u *UDPConn) submitRequest(idx int) error {
	r := &u.reqs[idx]
	// TODO: make a C struct instead of a Go struct, and pass that in, to simplify call sites.
	errno := C.submit_recvmsg_request(u.fd, u.ptr, &r.mhdr, &r.iov, &r.sa, (*C.char)(unsafe.Pointer(&r.buf[0])), C.int(len(r.buf)), C.size_t(idx))
	if errno < 0 {
		return fmt.Errorf("uring.submitRequest failed: %v", errno) // TODO: Improve
	}
	return nil
}

func (u *UDPConn) ReadFromNetaddr(buf []byte) (int, netaddr.IPPort, error) {
	if u.fd == 0 {
		return 0, netaddr.IPPort{}, errors.New("invalid uring.UDPConn")
	}
	nidx := C.receive_into(u.ptr)
	if int64(nidx) == -1 {
		return 0, netaddr.IPPort{}, errors.New("something wrong")
	}
	idx := uint32(nidx)
	n := uint32(nidx >> 32)
	r := &u.reqs[int(idx)]
	ip := C.ip(&r.sa)
	var ip4 [4]byte
	binary.BigEndian.PutUint32(ip4[:], uint32(ip))
	port := C.port(&r.sa)
	ipp := netaddr.IPPortFrom(netaddr.IPFrom4(ip4), uint16(port))
	copy(buf, r.buf[:n])
	// Queue up a new request.
	err := u.submitRequest(int(idx))
	if err != nil {
		panic("how should we handle this?")
	}
	return int(n), ipp, nil
}

func (u *UDPConn) Close() error {
	// fmt.Println("CLOSE URING", u)
	u.close.Do(func() {
		// Send a nop to unblock any outstanding readers.
		// Hope that we manage to close before any new readers appear.
		// Not sure exactly how this is supposed to work reliably...
		// I must be missing something.
		//
		// C.submit_nop_request(u.ptr)
		//
		// Update: this causes crashes, because of entirely predictable and predicted races.
		// The mystery about how to safely unblock all outstanding io_uring_wait_cqe calls remains...
		// fmt.Println("io_uring_queue_exit", u.ptr)
		C.io_uring_queue_exit(u.ptr)
		// fmt.Println("DONE io_uring_queue_exit", u.ptr)
		u.ptr = nil
		u.conn.Close()
		u.conn = nil
		u.file.Close()
		u.file = nil
		u.fd = 0
	})
	return nil
}

// Implement net.PacketConn, for convenience integrating with magicsock.

var _ net.PacketConn = (*UDPConn)(nil)

type udpAddr struct {
	ipp netaddr.IPPort
}

func (u udpAddr) Network() string { return "udp4" } // TODO: ipv6
func (u udpAddr) String() string  { return u.ipp.String() }

func (c *UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ipp, err := c.ReadFromNetaddr(p)
	if err != nil {
		return 0, nil, err
	}
	return n, udpAddr{ipp: ipp}, err
}

func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return c.conn.WriteTo(p, addr)
}

// LocalAddr returns the local network address.
func (c *UDPConn) LocalAddr() net.Addr { return c.local }

func (c *UDPConn) SetDeadline(t time.Time) error {
	panic("not implemented") // TODO: Implement
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	panic("not implemented") // TODO: Implement
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	panic("not implemented") // TODO: Implement
}
