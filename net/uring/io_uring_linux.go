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
	"reflect"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"inet.af/netaddr"
)

const bufferSize = device.MaxSegmentSize

// A UDPConn is a recv-only UDP fd manager.
// We'd like to enqueue a bunch of recv calls and deqeueue them later,
// but we have a problem with buffer management: We get our buffers just-in-time
// from wireguard-go, which means we have to make copies.
// That's OK for now, but later it could be a performance issue.
// For now, keep it simple and enqueue/dequeue in a single step.
type UDPConn struct {
	recvRing *C.go_uring
	sendRing *C.go_uring
	close    sync.Once
	conn     *net.UDPConn
	file     *os.File // must keep file from being GC'd
	fd       C.int
	local    net.Addr
	recvReqs [8]*C.goreq
	sendReqs [8]*C.goreq
	sendReqC chan int // indices into sendReqs
	is4      bool
}

func NewUDPConn(pconn net.PacketConn) (*UDPConn, error) {
	conn, ok := pconn.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("cannot use io_uring with conn of type %T", pconn)
	}
	// this is dumb
	local := conn.LocalAddr().String()
	ip, err := netaddr.ParseIPPort(local)
	if err != nil {
		return nil, fmt.Errorf("failed to parse UDPConn local addr %s as IP: %w", local, err)
	}
	ipVersion := 6
	if ip.IP().Is4() {
		ipVersion = 4
	}
	// TODO: probe for system capabilities: https://unixism.net/loti/tutorial/probe_liburing.html
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	recvRing := new(C.go_uring)
	sendRing := new(C.go_uring)

	fd := C.int(file.Fd())
	for _, r := range []*C.go_uring{recvRing, sendRing} {
		ret := C.initialize(r, fd)
		if ret < 0 {
			// TODO: free recvRing if sendRing initialize failed
			return nil, fmt.Errorf("uring initialization failed: %d", ret)
		}
	}
	u := &UDPConn{
		recvRing: recvRing,
		sendRing: sendRing,
		conn:     conn,
		file:     file,
		fd:       fd,
		local:    conn.LocalAddr(),
		is4:      ipVersion == 4,
	}

	// Initialize buffers
	for _, reqs := range []*[8]*C.goreq{&u.recvReqs, &u.sendReqs} {
		for i := range reqs {
			reqs[i] = C.initializeReq(bufferSize, C.int(ipVersion))
		}
	}

	// Initialize recv half.
	for i := range u.recvReqs {
		if err := u.submitRecvRequest(i); err != nil {
			u.Close() // TODO: will this crash?
			return nil, err
		}
	}
	// Initialize send half.
	u.sendReqC = make(chan int, len(u.sendReqs))
	for i := range u.sendReqs {
		u.sendReqC <- i
	}
	return u, nil
}

func (u *UDPConn) submitRecvRequest(idx int) error {
	// TODO: make a C struct instead of a Go struct, and pass that in, to simplify call sites.
	errno := C.submit_recvmsg_request(u.recvRing, u.recvReqs[idx], C.size_t(idx))
	if errno < 0 {
		return fmt.Errorf("uring.submitRecvRequest failed: %v", errno) // TODO: Improve
	}
	return nil
}

// TODO: replace with unsafe.Slice once we are using Go 1.17.

func sliceOf(ptr *C.char, n int) []byte {
	var b []byte
	h := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	h.Data = uintptr(unsafe.Pointer(ptr))
	h.Len = n
	h.Cap = n
	return b
}

func (u *UDPConn) ReadFromNetaddr(buf []byte) (int, netaddr.IPPort, error) {
	if u.fd == 0 {
		return 0, netaddr.IPPort{}, errors.New("invalid uring.UDPConn")
	}
	nidx := C.wait_completion(u.recvRing)
	n, idx, err := unpackNIdx(nidx)
	if err != nil {
		return 0, netaddr.IPPort{}, fmt.Errorf("ReadFromNetaddr: %v", err)
	}
	r := u.recvReqs[idx]

	var ip netaddr.IP
	var port uint16
	if u.is4 {
		// TODO: native go endianness conversion routines so we don't have to call ntohl, etc.
		ip = netaddr.IPFrom4(*(*[4]byte)((unsafe.Pointer)((&r.sa.sin_addr.s_addr))))
		port = uint16(C.ntohs(r.sa.sin_port))
	} else {
		ip = netaddr.IPFrom16(*(*[16]byte)((unsafe.Pointer)((&r.sa6.sin6_addr))))
		port = uint16(C.ntohs(r.sa6.sin6_port))
	}
	ipp := netaddr.IPPortFrom(ip, port)
	rbuf := sliceOf(r.buf, n)
	copy(buf, rbuf)
	// Queue up a new request.
	// TODO: Do this in a goroutine?
	err = u.submitRecvRequest(int(idx))
	if err != nil {
		panic("how should we handle this?")
	}
	return n, ipp, nil
}

func (u *UDPConn) Close() error {
	u.close.Do(func() {
		u.conn.Close()
		u.conn = nil
		// Send a nop to unblock any outstanding readers.
		// Hope that we manage to close before any new readers appear.
		// Not sure exactly how this is supposed to work reliably...
		// I must be missing something.
		//
		// C.submit_nop_request(u.ptr)
		//
		// Update: this causes crashes, because of entirely predictable and predicted races.
		// The mystery about how to safely unblock all outstanding io_uring_wait_cqe calls remains...
		C.io_uring_queue_exit(u.recvRing)
		C.io_uring_queue_exit(u.sendRing)
		u.recvRing = nil
		u.sendRing = nil
		u.file.Close()
		u.file = nil
		u.fd = 0

		// Free buffers
		for _, reqs := range []*[8]*C.goreq{&u.recvReqs, &u.sendReqs} {
			for _, r := range reqs {
				C.freeReq(r)
			}
		}
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

func (u *UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if u.fd == 0 {
		return 0, errors.New("invalid uring.UDPConn")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("cannot WriteTo net.Addr of type %T", addr)
	}
	// If we need a buffer, get a buffer, potentially blocking.
	var idx int
	select {
	case idx = <-u.sendReqC:
	default:
		// No request available. Get one from the kernel.
		nidx := C.wait_completion(u.sendRing)
		var err error
		_, idx, err = unpackNIdx(nidx)
		if err != nil {
			return 0, fmt.Errorf("some WriteTo failed, maybe long ago: %v", err)
		}
	}
	r := u.sendReqs[idx]
	// Do the write.
	rbuf := sliceOf(r.buf, len(p))
	copy(rbuf, p)

	if u.is4 {
		// TODO: native go endianness conversion routines so we don't have to call ntohl, etc.
		ipu32 := binary.BigEndian.Uint32(udpAddr.IP)
		r.sa.sin_addr.s_addr = C.htonl(C.uint32_t(ipu32))
		r.sa.sin_port = C.htons(C.uint16_t(udpAddr.Port))
		r.sa.sin_family = C.AF_INET
	} else {
		dst := (*[16]byte)((unsafe.Pointer)(&r.sa6.sin6_addr))
		src := (*[16]byte)((unsafe.Pointer)(&udpAddr.IP[0]))
		*dst = *src
		r.sa6.sin6_port = C.htons(C.uint16_t(udpAddr.Port))
		r.sa6.sin6_family = C.AF_INET6
	}
	C.submit_sendmsg_request(
		u.sendRing, // ring
		r,
		C.int(len(p)), // buffer len, ditto
		C.size_t(idx), // user data
	)
	// Get an extra buffer, if available.
	nidx := C.peek_completion(u.sendRing)
	if syscall.Errno(-nidx) == syscall.EAGAIN || syscall.Errno(-nidx) == syscall.EINTR {
		// Nothing waiting for us.
	} else {
		_, idx, err := unpackNIdx(nidx) // ignore errors here, this is best-effort only (TODO: right?)
		if err == nil {
			// Put the request buffer back in the usable queue.
			// Should never block, by construction.
			u.sendReqC <- idx
		}
	}
	return len(p), nil
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

// Files!

// A File is a write-only file fd manager.
// TODO: Support reads
// TODO: all the todos from UDPConn
type file struct {
	writeRing *C.go_uring
	readRing  *C.go_uring
	close     sync.Once
	file      *os.File // must keep file from being GC'd
	fd        C.int
	readReqs  [1]*C.goreq // Whoops! The kernel apparently cannot handle more than 1 concurrent preadv calls on a tun device!
	writeReqs [8]*C.goreq
	writeReqC chan int // indices into reqs
}

func newFile(f *os.File) (*file, error) {
	fd := C.int(f.Fd())
	u := &file{
		file: f,
		fd:   fd,
	}
	for _, ringPtr := range []**C.go_uring{&u.writeRing, &u.readRing} {
		r := new(C.go_uring)
		ret := C.initialize(r, fd)
		if ret < 0 {
			// TODO: handle unwinding partial initialization
			return nil, fmt.Errorf("uring initialization failed: %d", ret)
		}
		*ringPtr = r
	}

	// Initialize buffers
	for i := range &u.readReqs {
		u.readReqs[i] = C.initializeReq(bufferSize, 0)
	}
	for i := range &u.writeReqs {
		u.writeReqs[i] = C.initializeReq(bufferSize, 0)
	}

	// Initialize read half.
	for i := range u.readReqs {
		if err := u.submitReadvRequest(i); err != nil {
			u.Close() // TODO: will this crash?
			return nil, err
		}
	}

	u.writeReqC = make(chan int, len(u.writeReqs))
	for i := range u.writeReqs {
		u.writeReqC <- i
	}
	return u, nil
}

func (u *file) submitReadvRequest(idx int) error {
	// TODO: make a C struct instead of a Go struct, and pass that in, to simplify call sites.
	errno := C.submit_readv_request(u.readRing, u.readReqs[idx], C.size_t(idx))
	if errno < 0 {
		return fmt.Errorf("uring.submitReadvRequest failed: %v", errno) // TODO: Improve
	}
	return nil
}

func unpackNIdx(nidx C.uint64_t) (n, idx int, err error) {
	if int64(nidx) < 0 {
		return 0, 0, fmt.Errorf("error %d", int64(nidx))
	}
	return int(uint32(nidx >> 32)), int(uint32(nidx)), nil
}

type fileReq struct {
	iov C.go_iovec
	buf [device.MaxSegmentSize]byte
}

// Read data into buf[offset:].
// We are allowed to write junk into buf[offset-4:offset].
func (u *file) Read(buf []byte) (n int, err error) { // read a packet from the device (without any additional headers)
	if u.fd == 0 {
		return 0, errors.New("invalid uring.File")
	}
	nidx := C.wait_completion(u.readRing)
	n, idx, err := unpackNIdx(nidx)
	if err != nil || n < 4 {
		return 0, fmt.Errorf("Read: %v", err)
	}
	r := u.readReqs[idx]
	rbuf := sliceOf(r.buf, n)
	copy(buf, rbuf)
	// Queue up a new request.
	err = u.submitReadvRequest(int(idx))
	if err != nil {
		panic("how should we handle this?")
	}
	return n, nil
}

func (u *file) Write(buf []byte) (int, error) {
	if u.fd == 0 {
		return 0, errors.New("invalid uring.FileConn")
	}
	// If we need a buffer, get a buffer, potentially blocking.
	var idx int
	select {
	case idx = <-u.writeReqC:
	default:
		// No request available. Get one from the kernel.
		nidx := C.wait_completion(u.writeRing)
		var err error
		_, idx, err = unpackNIdx(nidx)
		if err != nil {
			return 0, fmt.Errorf("some write failed, maybe long ago: %v", err)
		}
	}
	r := u.writeReqs[idx]
	// Do the write.
	rbuf := sliceOf(r.buf, len(buf))
	copy(rbuf, buf)
	C.submit_writev_request(u.writeRing, r, C.int(len(buf)), C.size_t(idx))
	// Get an extra buffer, if available.
	nidx := C.peek_completion(u.writeRing)
	if syscall.Errno(-nidx) == syscall.EAGAIN || syscall.Errno(-nidx) == syscall.EINTR {
		// Nothing waiting for us.
	} else {
		_, idx, err := unpackNIdx(nidx) // ignore errors here, this is best-effort only (TODO: right?)
		if err == nil {
			// Put the request buffer back in the usable queue.
			// Should never block, by construction.
			u.writeReqC <- idx
		}
	}
	return len(buf), nil
}

// TODO: the TODOs from UDPConn.Close
func (u *file) Close() error {
	u.close.Do(func() {
		u.file.Close()
		// TODO: require kernel 5.5, send an abort SQE, handle aborts gracefully
		C.io_uring_queue_exit(u.readRing)
		C.io_uring_queue_exit(u.writeRing)
		u.readRing = nil
		u.writeRing = nil
		u.file = nil
		u.fd = 0

		// Free buffers
		for _, r := range u.readReqs {
			C.freeReq(r)
		}
		for _, r := range u.writeReqs {
			C.freeReq(r)
		}
	})
	return nil
}

// Wrap files into TUN devices.

func NewTUN(d tun.Device) (tun.Device, error) {
	nt, ok := d.(*tun.NativeTun)
	if !ok {
		return nil, fmt.Errorf("NewTUN only wraps *tun.NativeTun, got %T", d)
	}
	f, err := newFile(nt.File())
	if err != nil {
		return nil, err
	}
	v := reflect.ValueOf(nt)
	field, ok := v.Elem().Type().FieldByName("errors")
	if !ok {
		return nil, errors.New("could not find internal tun.NativeTun errors field")
	}
	ptr := unsafe.Pointer(nt)
	ptr = unsafe.Pointer(uintptr(ptr) + field.Offset) // TODO: switch to unsafe.Add with Go 1.17...as if that's the worst thing in this line
	c := *(*chan error)(ptr)
	return &TUN{d: nt, f: f, errors: c}, nil
}

// No nopi
type TUN struct {
	d      *tun.NativeTun
	f      *file
	errors chan error
}

func (t *TUN) File() *os.File {
	return t.f.file
}

func (t *TUN) Read(buf []byte, offset int) (int, error) {
	select {
	case err := <-t.errors:
		return 0, err
	default:
	}
	// TODO: upstream has graceful shutdown error handling here.
	buff := buf[offset-4:]
	n, err := t.f.Read(buff[:])
	if errors.Is(err, syscall.EBADFD) {
		err = os.ErrClosed
	}
	if n < 4 {
		n = 0
	} else {
		n -= 4
	}
	return n, err
}

func (t *TUN) Write(buf []byte, offset int) (int, error) {
	// below copied from wireguard-go NativeTun.Write

	// reserve space for header
	buf = buf[offset-4:]

	// add packet information header
	buf[0] = 0x00
	buf[1] = 0x00
	if buf[4]>>4 == ipv6.Version {
		buf[2] = 0x86
		buf[3] = 0xdd
	} else {
		buf[2] = 0x08
		buf[3] = 0x00
	}

	n, err := t.f.Write(buf)
	if errors.Is(err, syscall.EBADFD) {
		err = os.ErrClosed
	}
	return n, err
}

func (t *TUN) Flush() error           { return t.d.Flush() }
func (t *TUN) MTU() (int, error)      { return t.d.MTU() }
func (t *TUN) Name() (string, error)  { return t.d.Name() }
func (t *TUN) Events() chan tun.Event { return t.d.Events() }

func (t *TUN) Close() error {
	err1 := t.f.Close()
	err2 := t.d.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
