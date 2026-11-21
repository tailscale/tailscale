// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package msgx

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"tailscale.com/util/clientmetric"
	"tailscale.com/version"
)

// Client metrics, so that a change in kernel behavior in the wild shows up
// rather than silently disabling batching.
var (
	// metricSelfTestRan is 1 once the self-test has run in this process,
	// i.e. the process was eligible (not sandboxed) and tried the calls.
	metricSelfTestRan = clientmetric.NewGauge("msgx_selftest_ran")
	// metricSelfTestPassed is 1 if the self-test passed, 0 if it ran and
	// failed. It stays 0 if the self-test never ran.
	metricSelfTestPassed = clientmetric.NewGauge("msgx_selftest_passed")
	// metricSelfTestFailure is which step of the self-test failed, as a
	// [selfTestFailure], or 0 if it passed or never ran.
	metricSelfTestFailure = clientmetric.NewGauge("msgx_selftest_failure")
)

// selfTestFailure identifies which step of [selfTest] failed, for
// metricSelfTestFailure.
type selfTestFailure int64

const (
	selfTestPassed        selfTestFailure = 0
	selfTestSetupFailed   selfTestFailure = 1 // creating the loopback sockets
	selfTestSendFailed    selfTestFailure = 2 // sendmsg_x returned an error
	selfTestSendShort     selfTestFailure = 3 // sendmsg_x accepted nothing
	selfTestRecvFailed    selfTestFailure = 4 // recvmsg_x returned an error (including a timeout)
	selfTestRecvShort     selfTestFailure = 5 // recvmsg_x returned nothing
	selfTestCountMismatch selfTestFailure = 6 // wrong number of datagrams
	selfTestDataMismatch  selfTestFailure = 7 // wrong contents or length
	selfTestAddrMismatch  selfTestFailure = 8 // wrong source address
)

// selfTestError is an error from one step of [selfTest].
type selfTestError struct {
	step selfTestFailure
	err  error
}

func (e *selfTestError) Error() string { return e.err.Error() }
func (e *selfTestError) Unwrap() error { return e.err }

func stepErr(step selfTestFailure, format string, args ...any) error {
	return &selfTestError{step: step, err: fmt.Errorf(format, args...)}
}

// msghdrX is xnu's struct msghdr_x (bsd/sys/socket_private.h) for a 64-bit
// process: struct msghdr with a trailing msg_datalen, the byte count the
// kernel transferred for that message.
// sizeMsghdrX guards the overall size and [selfTest] verifies the kernel
// agrees at runtime.
type msghdrX struct {
	Name       unsafe.Pointer // msg_name: *syscall.RawSockaddrInet6 on input, or nil for sends
	Namelen    uint32         // msg_namelen
	_          [4]byte
	Iov        *syscall.Iovec // msg_iov
	Iovlen     int32          // msg_iovlen
	_          [4]byte
	Control    unsafe.Pointer // msg_control; must be nil for sends
	Controllen uint32         // msg_controllen
	Flags      int32          // msg_flags
	Datalen    uint64         // msg_datalen (size_t)
}

// sizeMsghdrX is sizeof(struct msghdr_x) on 64-bit Darwin: a 48-byte struct
// msghdr followed by an 8-byte msg_datalen.
const sizeMsghdrX = 56

// System call numbers for recvmsg_x and sendmsg_x, unchanged since OS X
// 10.10. These equal unix.SYS_RECVMSG_X and unix.SYS_SENDMSG_X, which are
// deprecated in x/sys in favor of libSystem wrappers that do not exist for
// these two entry points.
const (
	sysRecvmsgX = 480
	sysSendmsgX = 481
)

var _ [0]struct{} = [sizeMsghdrX - unsafe.Sizeof(msghdrX{})]struct{}{}

// callState is the per-call scratch memory for [Recv] and [Send]. The kernel
// is handed pointers into it, so it lives on the heap (Go's collector does
// not move heap objects) and is kept alive across the system call.
type callState struct {
	hdrs  [MaxBatch]msghdrX
	iovs  [MaxBatch]syscall.Iovec
	names [MaxBatch]syscall.RawSockaddrInet6
}

var statePool = sync.Pool{New: func() any { return new(callState) }}

var (
	availOnce sync.Once
	available bool
	availErr  error
)

// Available reports whether recvmsg_x and sendmsg_x may be used by this
// process. See the package documentation for the conditions. The result is
// computed once and does not change.
func Available() bool {
	availOnce.Do(func() {
		availErr = check()
		available = availErr == nil
	})
	return available
}

// UnavailableReason returns why [Available] is false, or nil if it is true.
func UnavailableReason() error {
	Available()
	return availErr
}

func check() error {
	// The system calls need no special privileges. The gating is about
	// where it's acceptable to use non-public kernel interfaces at all:
	// never from a sandboxed App Store process, ours or a third party's
	// embedding tsnet. Apple's App Sandbox sets APP_SANDBOX_CONTAINER_ID
	// in the environment of every sandboxed process.
	if version.IsSandboxedMacOS() {
		return errors.New("sandboxed macOS process")
	}
	if os.Getenv("APP_SANDBOX_CONTAINER_ID") != "" {
		return errors.New("process is in an App Sandbox container")
	}
	metricSelfTestRan.Set(1)
	err := selfTest()
	if err != nil {
		var ste *selfTestError
		if errors.As(err, &ste) {
			metricSelfTestFailure.Set(int64(ste.step))
		}
		return fmt.Errorf("self-test failed: %w", err)
	}
	metricSelfTestPassed.Set(1)
	return nil
}

// Recv receives up to len(msgs) datagrams from rc's socket in one system
// call, filling the N, Addr, and Flags fields of the entries it used, and
// returns how many. It blocks (parked on the network poller) until at least
// one datagram is available, and never returns zero without an error.
func Recv(rc syscall.RawConn, msgs []Message) (n int, err error) {
	if !Available() {
		return 0, ErrUnavailable
	}
	return recv(rc, msgs)
}

// recv is [Recv] without the availability check, for the self-test.
func recv(rc syscall.RawConn, msgs []Message) (n int, err error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if len(msgs) > MaxBatch {
		msgs = msgs[:MaxBatch]
	}
	st := statePool.Get().(*callState)
	defer statePool.Put(st)
	for i := range msgs {
		if len(msgs[i].Payload) == 0 {
			return 0, fmt.Errorf("msgx: message %d has an empty payload buffer", i)
		}
		st.iovs[i] = syscall.Iovec{Base: &msgs[i].Payload[0], Len: uint64(len(msgs[i].Payload))}
		st.hdrs[i] = msghdrX{
			Name:    unsafe.Pointer(&st.names[i]),
			Namelen: uint32(unsafe.Sizeof(st.names[i])),
			Iov:     &st.iovs[i],
			Iovlen:  1,
		}
	}
	var (
		r     uintptr
		errno syscall.Errno
	)
	rcErr := rc.Read(func(fd uintptr) bool {
		for {
			r, _, errno = syscall.Syscall6(sysRecvmsgX, fd, uintptr(unsafe.Pointer(&st.hdrs[0])), uintptr(len(msgs)), 0, 0, 0)
			if errno == syscall.EINTR {
				continue
			}
			return errno != syscall.EAGAIN
		}
	})
	runtime.KeepAlive(msgs)
	if rcErr != nil {
		return 0, rcErr
	}
	if errno != 0 {
		return 0, fmt.Errorf("msgx: recvmsg_x: %w", errno)
	}
	n = int(r)
	for i := range msgs[:n] {
		msgs[i].N = int(st.hdrs[i].Datalen)
		msgs[i].Flags = int(st.hdrs[i].Flags)
		msgs[i].Addr = sockaddrToAddrPort(&st.names[i], st.hdrs[i].Namelen)
	}
	return n, nil
}

// Send transmits up to [MaxBatch] of payloads on rc's connected socket in
// one system call and returns how many the kernel accepted, which may be
// fewer than offered; the caller retries the remainder.
//
// A partial batch is never reported as an error: once at least one datagram
// has been accepted, the kernel folds EAGAIN, ENOBUFS, EINTR, and EMSGSIZE
// on a later one into a short count (see the done label in sendmsg_x in
// xnu's bsd/kern/uipc_syscalls.c). So a non-nil error means nothing was
// sent. Of those, EAGAIN is handled here by parking on the network poller
// until the socket is writable; the rest are returned. ENOBUFS in
// particular is how Darwin reports a full interface output queue for UDP,
// and means the datagrams were dropped, not that the socket is broken.
//
// On a connected datagram socket the kernel builds all the packets in one
// pass (sosend_list); see [SendTo] for unconnected sockets.
func Send(rc syscall.RawConn, payloads [][]byte) (n int, err error) {
	if !Available() {
		return 0, ErrUnavailable
	}
	return send(rc, payloads, netip.AddrPort{})
}

// SendTo is like [Send] but for an unconnected socket: every payload is sent
// to addr. The kernel handles the messages one at a time internally (each
// with its own route lookup, as sendto(2) would), but in a single system
// call, with the same short-count semantics for errors after the first
// message.
func SendTo(rc syscall.RawConn, payloads [][]byte, addr netip.AddrPort) (n int, err error) {
	if !Available() {
		return 0, ErrUnavailable
	}
	if !addr.IsValid() {
		return 0, errors.New("msgx: SendTo: invalid address")
	}
	return send(rc, payloads, addr)
}

// send is [Send] (addr zero) or [SendTo] without the availability check.
func send(rc syscall.RawConn, payloads [][]byte, addr netip.AddrPort) (n int, err error) {
	if len(payloads) == 0 {
		return 0, nil
	}
	if len(payloads) > MaxBatch {
		payloads = payloads[:MaxBatch]
	}
	st := statePool.Get().(*callState)
	defer statePool.Put(st)
	var (
		name    unsafe.Pointer
		namelen uint32
	)
	if addr.IsValid() {
		namelen = addrPortToSockaddr(addr, &st.names[0])
		name = unsafe.Pointer(&st.names[0])
	}
	for i, p := range payloads {
		if len(p) == 0 {
			return 0, fmt.Errorf("msgx: payload %d is empty", i)
		}
		st.iovs[i] = syscall.Iovec{Base: &p[0], Len: uint64(len(p))}
		// Fields other than the address and iov must be zero on input.
		st.hdrs[i] = msghdrX{Name: name, Namelen: namelen, Iov: &st.iovs[i], Iovlen: 1}
	}
	var (
		r     uintptr
		errno syscall.Errno
	)
	rcErr := rc.Write(func(fd uintptr) bool {
		for {
			r, _, errno = syscall.Syscall6(sysSendmsgX, fd, uintptr(unsafe.Pointer(&st.hdrs[0])), uintptr(len(payloads)), 0, 0, 0)
			if errno == syscall.EINTR {
				continue
			}
			return errno != syscall.EAGAIN
		}
	})
	runtime.KeepAlive(payloads)
	if rcErr != nil {
		return 0, rcErr
	}
	if errno != 0 {
		return 0, fmt.Errorf("msgx: sendmsg_x: %w", errno)
	}
	return int(r), nil
}

// addrPortToSockaddr fills sa with ap as a sockaddr_in or sockaddr_in6 and
// returns the length the kernel should be told.
func addrPortToSockaddr(ap netip.AddrPort, sa *syscall.RawSockaddrInet6) uint32 {
	*sa = syscall.RawSockaddrInet6{}
	if ap.Addr().Is4() || ap.Addr().Is4In6() {
		sa4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		sa4.Len = syscall.SizeofSockaddrInet4
		sa4.Family = syscall.AF_INET
		sa4.Port = ntohs(ap.Port())
		sa4.Addr = ap.Addr().Unmap().As4()
		return syscall.SizeofSockaddrInet4
	}
	sa.Len = syscall.SizeofSockaddrInet6
	sa.Family = syscall.AF_INET6
	sa.Port = ntohs(ap.Port())
	sa.Addr = ap.Addr().As16()
	if z := ap.Addr().Zone(); z != "" {
		if n, err := strconv.Atoi(z); err == nil {
			sa.Scope_id = uint32(n)
		} else if ifi, err := net.InterfaceByName(z); err == nil {
			sa.Scope_id = uint32(ifi.Index)
		}
	}
	return syscall.SizeofSockaddrInet6
}

// sockaddrToAddrPort converts a sockaddr written by the kernel (of namelen
// bytes) to a netip.AddrPort, or the zero value if it is not an IP address.
func sockaddrToAddrPort(sa *syscall.RawSockaddrInet6, namelen uint32) netip.AddrPort {
	if namelen == 0 {
		return netip.AddrPort{}
	}
	switch sa.Family {
	case syscall.AF_INET:
		sa4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		return netip.AddrPortFrom(netip.AddrFrom4(sa4.Addr), ntohs(sa4.Port))
	case syscall.AF_INET6:
		addr := netip.AddrFrom16(sa.Addr)
		if sa.Scope_id != 0 {
			addr = addr.WithZone(fmt.Sprint(sa.Scope_id))
		}
		return netip.AddrPortFrom(addr, ntohs(sa.Port))
	}
	return netip.AddrPort{}
}

// ntohs converts a port stored in network byte order in a sockaddr's uint16
// field, as Go's syscall package exposes it, to host order.
func ntohs(p uint16) uint16 {
	return p>>8 | p<<8
}

// selfTest exchanges datagrams over loopback with sendmsg_x and recvmsg_x
// and checks that the kernel reported what was sent.
func selfTest() error {
	recvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return stepErr(selfTestSetupFailed, "listen: %w", err)
	}
	defer recvConn.Close()
	sendConn, err := net.DialUDP("udp4", nil, recvConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return stepErr(selfTestSetupFailed, "dial: %w", err)
	}
	defer sendConn.Close()
	sendRC, err := sendConn.SyscallConn()
	if err != nil {
		return stepErr(selfTestSetupFailed, "%w", err)
	}
	recvRC, err := recvConn.SyscallConn()
	if err != nil {
		return stepErr(selfTestSetupFailed, "%w", err)
	}
	want := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	for rem := want; len(rem) > 0; {
		n, err := send(sendRC, rem, netip.AddrPort{})
		if err != nil {
			return stepErr(selfTestSendFailed, "sendmsg_x: %w", err)
		}
		if n == 0 {
			return stepErr(selfTestSendShort, "sendmsg_x accepted no datagrams")
		}
		rem = rem[n:]
	}
	recvConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgs := make([]Message, len(want)+1)
	for i := range msgs {
		msgs[i].Payload = make([]byte, 64)
	}
	got := 0
	for got < len(want) {
		n, err := recv(recvRC, msgs[got:])
		if err != nil {
			return stepErr(selfTestRecvFailed, "recvmsg_x: %w", err)
		}
		if n == 0 {
			return stepErr(selfTestRecvShort, "recvmsg_x returned no datagrams")
		}
		got += n
	}
	if got != len(want) {
		return stepErr(selfTestCountMismatch, "received %d datagrams, want %d", got, len(want))
	}
	from := sendConn.LocalAddr().(*net.UDPAddr).AddrPort()
	for i, w := range want {
		m := msgs[i]
		if m.N != len(w) || string(m.Payload[:m.N]) != string(w) {
			return stepErr(selfTestDataMismatch, "datagram %d: got %q, want %q", i, m.Payload[:m.N], w)
		}
		if m.Addr != from {
			return stepErr(selfTestAddrMismatch, "datagram %d: source %v, want %v", i, m.Addr, from)
		}
	}
	return nil
}
