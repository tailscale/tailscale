/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/conn/winrio"
)

const (
	packetsPerRing = 1024
	bytesPerPacket = 2048 - 32
	receiveSpins   = 15
)

type ringPacket struct {
	addr WinRingEndpoint
	data [bytesPerPacket]byte
}

type ringBuffer struct {
	packets    uintptr
	head, tail uint32
	id         winrio.BufferId
	iocp       windows.Handle
	isFull     bool
	cq         winrio.Cq
	mu         sync.Mutex
	overlapped windows.Overlapped
}

func (rb *ringBuffer) Push() *ringPacket {
	for rb.isFull {
		panic("ring is full")
	}
	ret := (*ringPacket)(unsafe.Pointer(rb.packets + (uintptr(rb.tail%packetsPerRing) * unsafe.Sizeof(ringPacket{}))))
	rb.tail += 1
	if rb.tail%packetsPerRing == rb.head%packetsPerRing {
		rb.isFull = true
	}
	return ret
}

func (rb *ringBuffer) Return(count uint32) {
	if rb.head%packetsPerRing == rb.tail%packetsPerRing && !rb.isFull {
		return
	}
	rb.head += count
	rb.isFull = false
}

type afWinRingBind struct {
	sock      windows.Handle
	rx, tx    ringBuffer
	rq        winrio.Rq
	mu        sync.Mutex
	blackhole bool
}

// WinRingBind uses Windows registered I/O for fast ring buffered networking.
type WinRingBind struct {
	v4, v6 afWinRingBind
	mu     sync.RWMutex
	isOpen uint32
}

func NewDefaultBind() Bind { return NewWinRingBind() }

func NewWinRingBind() Bind {
	if !winrio.Initialize() {
		return NewStdNetBind()
	}
	return new(WinRingBind)
}

type WinRingEndpoint struct {
	family uint16
	data   [30]byte
}

var _ Bind = (*WinRingBind)(nil)
var _ Endpoint = (*WinRingEndpoint)(nil)

func (*WinRingBind) ParseEndpoint(s string) (Endpoint, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	host16, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return nil, err
	}
	port16, err := windows.UTF16PtrFromString(port)
	if err != nil {
		return nil, err
	}
	hints := windows.AddrinfoW{
		Flags:    windows.AI_NUMERICHOST,
		Family:   windows.AF_UNSPEC,
		Socktype: windows.SOCK_DGRAM,
		Protocol: windows.IPPROTO_UDP,
	}
	var addrinfo *windows.AddrinfoW
	err = windows.GetAddrInfoW(host16, port16, &hints, &addrinfo)
	if err != nil {
		return nil, err
	}
	defer windows.FreeAddrInfoW(addrinfo)
	if (addrinfo.Family != windows.AF_INET && addrinfo.Family != windows.AF_INET6) || addrinfo.Addrlen > unsafe.Sizeof(WinRingEndpoint{}) {
		return nil, windows.ERROR_INVALID_ADDRESS
	}
	var dst [unsafe.Sizeof(WinRingEndpoint{})]byte
	copy(dst[:], unsafe.Slice((*byte)(unsafe.Pointer(addrinfo.Addr)), addrinfo.Addrlen))
	return (*WinRingEndpoint)(unsafe.Pointer(&dst[0])), nil
}

func (*WinRingEndpoint) ClearSrc() {}

func (e *WinRingEndpoint) DstIP() net.IP {
	switch e.family {
	case windows.AF_INET:
		return append([]byte{}, e.data[2:6]...)
	case windows.AF_INET6:
		return append([]byte{}, e.data[6:22]...)
	}
	return nil
}

func (e *WinRingEndpoint) SrcIP() net.IP {
	return nil // not supported
}

func (e *WinRingEndpoint) DstToBytes() []byte {
	switch e.family {
	case windows.AF_INET:
		b := make([]byte, 0, 6)
		b = append(b, e.data[2:6]...)
		b = append(b, e.data[1], e.data[0])
		return b
	case windows.AF_INET6:
		b := make([]byte, 0, 18)
		b = append(b, e.data[6:22]...)
		b = append(b, e.data[1], e.data[0])
		return b
	}
	return nil
}

func (e *WinRingEndpoint) DstToString() string {
	switch e.family {
	case windows.AF_INET:
		addr := net.UDPAddr{IP: e.data[2:6], Port: int(binary.BigEndian.Uint16(e.data[0:2]))}
		return addr.String()
	case windows.AF_INET6:
		var zone string
		if scope := *(*uint32)(unsafe.Pointer(&e.data[22])); scope > 0 {
			zone = strconv.FormatUint(uint64(scope), 10)
		}
		addr := net.UDPAddr{IP: e.data[6:22], Zone: zone, Port: int(binary.BigEndian.Uint16(e.data[0:2]))}
		return addr.String()
	}
	return ""
}

func (e *WinRingEndpoint) SrcToString() string {
	return ""
}

func (ring *ringBuffer) CloseAndZero() {
	if ring.cq != 0 {
		winrio.CloseCompletionQueue(ring.cq)
		ring.cq = 0
	}
	if ring.iocp != 0 {
		windows.CloseHandle(ring.iocp)
		ring.iocp = 0
	}
	if ring.id != 0 {
		winrio.DeregisterBuffer(ring.id)
		ring.id = 0
	}
	if ring.packets != 0 {
		windows.VirtualFree(ring.packets, 0, windows.MEM_RELEASE)
		ring.packets = 0
	}
	ring.head = 0
	ring.tail = 0
	ring.isFull = false
}

func (bind *afWinRingBind) CloseAndZero() {
	bind.rx.CloseAndZero()
	bind.tx.CloseAndZero()
	if bind.sock != 0 {
		windows.CloseHandle(bind.sock)
		bind.sock = 0
	}
	bind.blackhole = false
}

func (bind *WinRingBind) closeAndZero() {
	atomic.StoreUint32(&bind.isOpen, 0)
	bind.v4.CloseAndZero()
	bind.v6.CloseAndZero()
}

func (ring *ringBuffer) Open() error {
	var err error
	packetsLen := unsafe.Sizeof(ringPacket{}) * packetsPerRing
	ring.packets, err = windows.VirtualAlloc(0, packetsLen, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return err
	}
	ring.id, err = winrio.RegisterPointer(unsafe.Pointer(ring.packets), uint32(packetsLen))
	if err != nil {
		return err
	}
	ring.iocp, err = windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 0)
	if err != nil {
		return err
	}
	ring.cq, err = winrio.CreateIOCPCompletionQueue(packetsPerRing, ring.iocp, 0, &ring.overlapped)
	if err != nil {
		return err
	}
	return nil
}

func (bind *afWinRingBind) Open(family int32, sa windows.Sockaddr) (windows.Sockaddr, error) {
	var err error
	bind.sock, err = winrio.Socket(family, windows.SOCK_DGRAM, windows.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	err = bind.rx.Open()
	if err != nil {
		return nil, err
	}
	err = bind.tx.Open()
	if err != nil {
		return nil, err
	}
	bind.rq, err = winrio.CreateRequestQueue(bind.sock, packetsPerRing, 1, packetsPerRing, 1, bind.rx.cq, bind.tx.cq, 0)
	if err != nil {
		return nil, err
	}
	err = windows.Bind(bind.sock, sa)
	if err != nil {
		return nil, err
	}
	sa, err = windows.Getsockname(bind.sock)
	if err != nil {
		return nil, err
	}
	return sa, nil
}

func (bind *WinRingBind) Open(port uint16) (recvFns []ReceiveFunc, selectedPort uint16, err error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	defer func() {
		if err != nil {
			bind.closeAndZero()
		}
	}()
	if atomic.LoadUint32(&bind.isOpen) != 0 {
		return nil, 0, ErrBindAlreadyOpen
	}
	var sa windows.Sockaddr
	sa, err = bind.v4.Open(windows.AF_INET, &windows.SockaddrInet4{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	sa, err = bind.v6.Open(windows.AF_INET6, &windows.SockaddrInet6{Port: sa.(*windows.SockaddrInet4).Port})
	if err != nil {
		return nil, 0, err
	}
	selectedPort = uint16(sa.(*windows.SockaddrInet6).Port)
	for i := 0; i < packetsPerRing; i++ {
		err = bind.v4.InsertReceiveRequest()
		if err != nil {
			return nil, 0, err
		}
		err = bind.v6.InsertReceiveRequest()
		if err != nil {
			return nil, 0, err
		}
	}
	atomic.StoreUint32(&bind.isOpen, 1)
	return []ReceiveFunc{bind.receiveIPv4, bind.receiveIPv6}, selectedPort, err
}

func (bind *WinRingBind) Close() error {
	bind.mu.RLock()
	if atomic.LoadUint32(&bind.isOpen) != 1 {
		bind.mu.RUnlock()
		return nil
	}
	atomic.StoreUint32(&bind.isOpen, 2)
	windows.PostQueuedCompletionStatus(bind.v4.rx.iocp, 0, 0, nil)
	windows.PostQueuedCompletionStatus(bind.v4.tx.iocp, 0, 0, nil)
	windows.PostQueuedCompletionStatus(bind.v6.rx.iocp, 0, 0, nil)
	windows.PostQueuedCompletionStatus(bind.v6.tx.iocp, 0, 0, nil)
	bind.mu.RUnlock()
	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.closeAndZero()
	return nil
}

func (bind *WinRingBind) SetMark(mark uint32) error {
	return nil
}

func (bind *afWinRingBind) InsertReceiveRequest() error {
	packet := bind.rx.Push()
	dataBuffer := &winrio.Buffer{
		Id:     bind.rx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.data[0])) - bind.rx.packets),
		Length: uint32(len(packet.data)),
	}
	addressBuffer := &winrio.Buffer{
		Id:     bind.rx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.addr)) - bind.rx.packets),
		Length: uint32(unsafe.Sizeof(packet.addr)),
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	return winrio.ReceiveEx(bind.rq, dataBuffer, 1, nil, addressBuffer, nil, nil, 0, uintptr(unsafe.Pointer(packet)))
}

//go:linkname procyield runtime.procyield
func procyield(cycles uint32)

func (bind *afWinRingBind) Receive(buf []byte, isOpen *uint32) (int, Endpoint, error) {
	if atomic.LoadUint32(isOpen) != 1 {
		return 0, nil, net.ErrClosed
	}
	bind.rx.mu.Lock()
	defer bind.rx.mu.Unlock()

	var err error
	var count uint32
	var results [1]winrio.Result
retry:
	count = 0
	for tries := 0; count == 0 && tries < receiveSpins; tries++ {
		if tries > 0 {
			if atomic.LoadUint32(isOpen) != 1 {
				return 0, nil, net.ErrClosed
			}
			procyield(1)
		}
		count = winrio.DequeueCompletion(bind.rx.cq, results[:])
	}
	if count == 0 {
		err = winrio.Notify(bind.rx.cq)
		if err != nil {
			return 0, nil, err
		}
		var bytes uint32
		var key uintptr
		var overlapped *windows.Overlapped
		err = windows.GetQueuedCompletionStatus(bind.rx.iocp, &bytes, &key, &overlapped, windows.INFINITE)
		if err != nil {
			return 0, nil, err
		}
		if atomic.LoadUint32(isOpen) != 1 {
			return 0, nil, net.ErrClosed
		}
		count = winrio.DequeueCompletion(bind.rx.cq, results[:])
		if count == 0 {
			return 0, nil, io.ErrNoProgress

		}
	}
	bind.rx.Return(1)
	err = bind.InsertReceiveRequest()
	if err != nil {
		return 0, nil, err
	}
	// We limit the MTU well below the 65k max for practicality, but this means a remote host can still send us
	// huge packets. Just try again when this happens. The infinite loop this could cause is still limited to
	// attacker bandwidth, just like the rest of the receive path.
	if windows.Errno(results[0].Status) == windows.WSAEMSGSIZE {
		if atomic.LoadUint32(isOpen) != 1 {
			return 0, nil, net.ErrClosed
		}
		goto retry
	}
	if results[0].Status != 0 {
		return 0, nil, windows.Errno(results[0].Status)
	}
	packet := (*ringPacket)(unsafe.Pointer(uintptr(results[0].RequestContext)))
	ep := packet.addr
	n := copy(buf, packet.data[:results[0].BytesTransferred])
	return n, &ep, nil
}

func (bind *WinRingBind) receiveIPv4(buf []byte) (int, Endpoint, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	return bind.v4.Receive(buf, &bind.isOpen)
}

func (bind *WinRingBind) receiveIPv6(buf []byte) (int, Endpoint, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	return bind.v6.Receive(buf, &bind.isOpen)
}

func (bind *afWinRingBind) Send(buf []byte, nend *WinRingEndpoint, isOpen *uint32) error {
	if atomic.LoadUint32(isOpen) != 1 {
		return net.ErrClosed
	}
	if len(buf) > bytesPerPacket {
		return io.ErrShortBuffer
	}
	bind.tx.mu.Lock()
	defer bind.tx.mu.Unlock()
	var results [packetsPerRing]winrio.Result
	count := winrio.DequeueCompletion(bind.tx.cq, results[:])
	if count == 0 && bind.tx.isFull {
		err := winrio.Notify(bind.tx.cq)
		if err != nil {
			return err
		}
		var bytes uint32
		var key uintptr
		var overlapped *windows.Overlapped
		err = windows.GetQueuedCompletionStatus(bind.tx.iocp, &bytes, &key, &overlapped, windows.INFINITE)
		if err != nil {
			return err
		}
		if atomic.LoadUint32(isOpen) != 1 {
			return net.ErrClosed
		}
		count = winrio.DequeueCompletion(bind.tx.cq, results[:])
		if count == 0 {
			return io.ErrNoProgress
		}
	}
	if count > 0 {
		bind.tx.Return(count)
	}
	packet := bind.tx.Push()
	packet.addr = *nend
	copy(packet.data[:], buf)
	dataBuffer := &winrio.Buffer{
		Id:     bind.tx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.data[0])) - bind.tx.packets),
		Length: uint32(len(buf)),
	}
	addressBuffer := &winrio.Buffer{
		Id:     bind.tx.id,
		Offset: uint32(uintptr(unsafe.Pointer(&packet.addr)) - bind.tx.packets),
		Length: uint32(unsafe.Sizeof(packet.addr)),
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	return winrio.SendEx(bind.rq, dataBuffer, 1, nil, addressBuffer, nil, nil, 0, 0)
}

func (bind *WinRingBind) Send(buf []byte, endpoint Endpoint) error {
	nend, ok := endpoint.(*WinRingEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	switch nend.family {
	case windows.AF_INET:
		if bind.v4.blackhole {
			return nil
		}
		return bind.v4.Send(buf, nend, &bind.isOpen)
	case windows.AF_INET6:
		if bind.v6.blackhole {
			return nil
		}
		return bind.v6.Send(buf, nend, &bind.isOpen)
	}
	return nil
}

func (bind *StdNetBind) BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	sysconn, err := bind.ipv4.SyscallConn()
	if err != nil {
		return err
	}
	err2 := sysconn.Control(func(fd uintptr) {
		err = bindSocketToInterface4(windows.Handle(fd), interfaceIndex)
	})
	if err2 != nil {
		return err2
	}
	if err != nil {
		return err
	}
	bind.blackhole4 = blackhole
	return nil
}

func (bind *StdNetBind) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	sysconn, err := bind.ipv6.SyscallConn()
	if err != nil {
		return err
	}
	err2 := sysconn.Control(func(fd uintptr) {
		err = bindSocketToInterface6(windows.Handle(fd), interfaceIndex)
	})
	if err2 != nil {
		return err2
	}
	if err != nil {
		return err
	}
	bind.blackhole6 = blackhole
	return nil
}
func (bind *WinRingBind) BindSocketToInterface4(interfaceIndex uint32, blackhole bool) error {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if atomic.LoadUint32(&bind.isOpen) != 1 {
		return net.ErrClosed
	}
	err := bindSocketToInterface4(bind.v4.sock, interfaceIndex)
	if err != nil {
		return err
	}
	bind.v4.blackhole = blackhole
	return nil
}

func (bind *WinRingBind) BindSocketToInterface6(interfaceIndex uint32, blackhole bool) error {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if atomic.LoadUint32(&bind.isOpen) != 1 {
		return net.ErrClosed
	}
	err := bindSocketToInterface6(bind.v6.sock, interfaceIndex)
	if err != nil {
		return err
	}
	bind.v6.blackhole = blackhole
	return nil
}

func bindSocketToInterface4(handle windows.Handle, interfaceIndex uint32) error {
	const IP_UNICAST_IF = 31
	/* MSDN says for IPv4 this needs to be in net byte order, so that it's like an IP address with leading zeros. */
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], interfaceIndex)
	interfaceIndex = *(*uint32)(unsafe.Pointer(&bytes[0]))
	err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, IP_UNICAST_IF, int(interfaceIndex))
	if err != nil {
		return err
	}
	return nil
}

func bindSocketToInterface6(handle windows.Handle, interfaceIndex uint32) error {
	const IPV6_UNICAST_IF = 31
	return windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, IPV6_UNICAST_IF, int(interfaceIndex))
}
