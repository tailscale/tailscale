package uring

// #cgo LDFLAGS: -luring
// #include "io_uring_linux.c"
import "C"

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/device"
	"inet.af/netaddr"
	"tailscale.com/syncs"
	"tailscale.com/util/endian"
)

const bufferSize = device.MaxSegmentSize

// A UDPConn is a UDP connection that uses io_uring to send and receive packets.
type UDPConn struct {
	// We have two urings so that we don't have to demux completion events.

	// recvRing is the uring for recvmsg calls.
	recvRing *C.go_uring
	// sendRing is the uring for sendmsg calls.
	sendRing writeRing

	// close ensures that connection closes occur exactly once.
	close sync.Once
	// closed indicates whether the connection has been closed.
	closed syncs.AtomicBool
	// shutdown is a sequence of funcs to be called when the UDPConn closes.
	shutdown []func()

	// file is the os file underlying this connection.
	file *os.File
	// local is the local address of this UDPConn.
	local net.Addr
	// is4 indicates whether the conn is an IPv4 connection.
	is4 bool

	// recvReqs is an array of re-usable UDP recvmsg requests.
	// We attempt to keep them all queued up for the kernel to fulfill.
	// The array length is tied to the size of the uring.
	recvReqs [8]*C.goreq
	// sendReqs is an array of re-usable UDP sendmsg requests.
	// We dispatch them to the kernel as writes are requested.
	// The array length is tied to the size of the uring.
	sendReqs [8]*C.goreq
	// sendReqC is a channel containing indices into sendReqs
	// that are free to use (that is, not in the kernel).
	sendReqC chan int

	// refcount counts the number of outstanding read/write requests.
	// refcount is used for graceful shutdown.
	// The pattern (very roughly) is:
	//
	//   func readOrWrite() {
	//     refcount++
	//     defer refcount--
	//     if closed {
	//       return
	//     }
	//     // ...
	//   }
	//
	// Close sets closed to true and polls until refcount hits zero.
	// Once refcount hits zero, there are no ongoing reads or writes.
	// Any future reads or writes will exit immediately (because closed is true),
	// so resources used by reads and writes may be freed.
	// The polling is unfortunate, but it occurs only during Close, is fast,
	// and avoids ugly sequencing issues around canceling outstanding io_uring submissions.
	//
	// (The obvious alternative is to use a sync.RWMutex, but that has a chicken-and-egg problem.
	// Reads/writes must take an rlock, but Close cannot take a wlock under all the rlocks are released,
	// but Close cannot issue cancellations to release the rlocks without first taking a wlock.)
	refcount syncs.AtomicInt32
}

func NewUDPConn(pconn net.PacketConn) (*UDPConn, error) {
	conn, ok := pconn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("cannot use io_uring with conn of type %T", pconn)
	}
	local := conn.LocalAddr()
	udpAddr, ok := local.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("cannot use io_uring with conn.LocalAddr of type %T", local)
	}

	// TODO: probe for system capabilities: https://unixism.net/loti/tutorial/probe_liburing.html

	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	// conn.File dup'd the conn's fd. We no longer need the original conn.
	conn.Close()

	u := &UDPConn{
		recvRing: new(C.go_uring),
		file:     file,
		local:    local,
		is4:      len(udpAddr.IP) == 4,
	}
	u.sendRing.ring = new(C.go_uring)

	fd := file.Fd()
	u.shutdown = append(u.shutdown, func() {
		file.Close()
	})

	if ret := C.initialize(u.recvRing, C.int(fd)); ret < 0 {
		u.doShutdown()
		return nil, fmt.Errorf("recvRing initialization failed: %w", syscall.Errno(-ret))
	}
	u.shutdown = append(u.shutdown, func() {
		C.io_uring_queue_exit(u.recvRing)
	})

	if ret := C.initialize(u.sendRing.ring, C.int(fd)); ret < 0 {
		u.doShutdown()
		return nil, fmt.Errorf("sendRing initialization failed: %w", syscall.Errno(-ret))
	}
	u.shutdown = append(u.shutdown, func() {
		C.io_uring_queue_exit(u.sendRing.ring)
	})

	// Initialize buffers
	for i := range u.recvReqs {
		u.recvReqs[i] = C.initializeReq(bufferSize, C.size_t(i), C.int(len(udpAddr.IP)))
	}
	u.sendRing.initReqs(len(udpAddr.IP))
	u.shutdown = append(u.shutdown, func() {
		for _, r := range u.recvReqs {
			C.freeReq(r)
		}
		u.sendRing.freeReqs()
	})

	// Initialize recv half.
	for i := range u.recvReqs {
		if err := u.submitRecvRequest(i); err != nil {
			u.doShutdown()
			return nil, err
		}
	}
	return u, nil
}

func (u *UDPConn) submitRecvRequest(idx int) error {
	errno := C.submit_recvmsg_request(u.recvRing, u.recvReqs[idx])
	if errno < 0 {
		return fmt.Errorf("uring.submitRecvRequest failed: %w", syscall.Errno(-errno))
	}
	atomic.AddInt32(u.recvReqInKernel(idx), 1) // TODO: CAS?
	return nil
}

func (u *UDPConn) recvReqInKernel(idx int) *int32 {
	return (*int32)(unsafe.Pointer(&u.recvReqs[idx].in_kernel))
}

func (u *UDPConn) ReadFromNetaddr(buf []byte) (int, netaddr.IPPort, error) {
	// The docs for the u.refcount field document this prologue.
	u.refcount.Add(1)
	defer u.refcount.Add(-1)
	if u.closed.Get() {
		return 0, netaddr.IPPort{}, net.ErrClosed
	}

	n, idx, err := waitCompletion(u.recvRing)
	if errors.Is(err, syscall.ECANCELED) {
		atomic.AddInt32(u.recvReqInKernel(idx), -1)
		return 0, netaddr.IPPort{}, net.ErrClosed
	}
	if err != nil {
		// io_uring failed to run our syscall.
		return 0, netaddr.IPPort{}, fmt.Errorf("ReadFromNetaddr io_uring could not run syscall: %w", err)
	}
	atomic.AddInt32(u.recvReqInKernel(idx), -1)
	if n < 0 {
		// io_uring ran our syscall, which failed.
		// Best effort attempt not to leak idx.
		u.submitRecvRequest(int(idx))
		return 0, netaddr.IPPort{}, fmt.Errorf("ReadFromNetaddr syscall failed: %w", syscall.Errno(-n))
	}
	r := u.recvReqs[idx]
	var ip netaddr.IP
	var port uint16
	if u.is4 {
		ip = netaddr.IPFrom4(*(*[4]byte)((unsafe.Pointer)((&r.sa.sin_addr.s_addr))))
		port = endian.Ntoh16(uint16(r.sa.sin_port))
	} else {
		ip = netaddr.IPFrom16(*(*[16]byte)((unsafe.Pointer)((&r.sa6.sin6_addr))))
		port = endian.Ntoh16(uint16(r.sa6.sin6_port))
	}
	ipp := netaddr.IPPortFrom(ip, port)
	// Copy the data to the buffer provided by wireguard-go.
	// Maybe some sparkling day this copy wil be the slowest thing in our stack.
	// It's not even on the radar now.
	rbuf := sliceOf(r.buf, n)
	copy(buf, rbuf)
	// Queue up a new request.
	if err := u.submitRecvRequest(int(idx)); err != nil {
		// Aggressively return this error.
		// The error will bubble up and cause the entire conn to be closed down,
		// so it doesn't matter that we lost a packet here.
		return 0, netaddr.IPPort{}, err
	}
	return n, ipp, nil
}

func (c *UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, ipp, err := c.ReadFromNetaddr(p)
	if err != nil {
		return 0, nil, err
	}
	return n, ipp.UDPAddr(), err
}

func (u *UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// The docs for the u.refcount field document this prologue.
	u.refcount.Add(1)
	defer u.refcount.Add(-1)
	if u.closed.Get() {
		return 0, net.ErrClosed
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("cannot WriteTo net.Addr of type %T", addr)
	}

	// Get a req, blocking as needed.
	r, err := u.sendRing.getReq()
	if err != nil {
		return 0, err
	}
	// Do the write.
	rbuf := sliceOf(r.buf, len(p))
	copy(rbuf, p)

	if u.is4 {
		dst := (*[4]byte)((unsafe.Pointer)(&r.sa.sin_addr.s_addr))
		src := (*[4]byte)((unsafe.Pointer)(&udpAddr.IP[0]))
		*dst = *src
		r.sa.sin_port = C.uint16_t(endian.Hton16(uint16(udpAddr.Port)))
		r.sa.sin_family = C.AF_INET
	} else {
		dst := (*[16]byte)((unsafe.Pointer)(&r.sa6.sin6_addr))
		src := (*[16]byte)((unsafe.Pointer)(&udpAddr.IP[0]))
		*dst = *src
		r.sa6.sin6_port = C.uint16_t(endian.Hton16(uint16(udpAddr.Port)))
		r.sa6.sin6_family = C.AF_INET6
	}
	C.submit_sendmsg_request(u.sendRing.ring, r, C.int(len(p)))
	// Get an extra buffer, if available.
	u.sendRing.prefetch()
	return len(p), nil
}

func (u *UDPConn) Close() error {
	u.close.Do(func() {
		// Announce to readers and writers that we are closing down.
		// Busy loop until all reads and writes are unblocked.
		// See the docs for u.refcount.
		u.closed.Set(true)
		for {
			// Request that the kernel cancel all submitted reads. (Writes don't block indefinitely.)
			for idx := range u.recvReqs {
				if atomic.LoadInt32(u.recvReqInKernel(idx)) != 0 {
					C.submit_cancel_request(u.recvRing, C.size_t(idx))
				}
			}
			if u.refcount.Get() == 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		// Do the rest of the shutdown.
		u.doShutdown()
	})
	return nil
}

func (u *UDPConn) doShutdown() {
	for _, fn := range u.shutdown {
		fn()
	}
}

// Ensure that UDPConn implements net.PacketConn.
var _ net.PacketConn = (*UDPConn)(nil)

func (c *UDPConn) LocalAddr() net.Addr                { return c.local }
func (c *UDPConn) SetDeadline(t time.Time) error      { panic("not implemented") }
func (c *UDPConn) SetReadDeadline(t time.Time) error  { panic("not implemented") }
func (c *UDPConn) SetWriteDeadline(t time.Time) error { panic("not implemented") }
