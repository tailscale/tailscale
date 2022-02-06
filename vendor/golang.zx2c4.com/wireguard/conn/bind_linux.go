/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package conn

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ipv4Source struct {
	Src     [4]byte
	Ifindex int32
}

type ipv6Source struct {
	src [16]byte
	// ifindex belongs in dst.ZoneId
}

type LinuxSocketEndpoint struct {
	mu   sync.Mutex
	dst  [unsafe.Sizeof(unix.SockaddrInet6{})]byte
	src  [unsafe.Sizeof(ipv6Source{})]byte
	isV6 bool
}

func (endpoint *LinuxSocketEndpoint) Src4() *ipv4Source         { return endpoint.src4() }
func (endpoint *LinuxSocketEndpoint) Dst4() *unix.SockaddrInet4 { return endpoint.dst4() }
func (endpoint *LinuxSocketEndpoint) IsV6() bool                { return endpoint.isV6 }

func (endpoint *LinuxSocketEndpoint) src4() *ipv4Source {
	return (*ipv4Source)(unsafe.Pointer(&endpoint.src[0]))
}

func (endpoint *LinuxSocketEndpoint) src6() *ipv6Source {
	return (*ipv6Source)(unsafe.Pointer(&endpoint.src[0]))
}

func (endpoint *LinuxSocketEndpoint) dst4() *unix.SockaddrInet4 {
	return (*unix.SockaddrInet4)(unsafe.Pointer(&endpoint.dst[0]))
}

func (endpoint *LinuxSocketEndpoint) dst6() *unix.SockaddrInet6 {
	return (*unix.SockaddrInet6)(unsafe.Pointer(&endpoint.dst[0]))
}

// LinuxSocketBind uses sendmsg and recvmsg to implement a full bind with sticky sockets on Linux.
type LinuxSocketBind struct {
	// mu guards sock4 and sock6 and the associated fds.
	// As long as someone holds mu (read or write), the associated fds are valid.
	mu    sync.RWMutex
	sock4 int
	sock6 int
}

func NewLinuxSocketBind() Bind { return &LinuxSocketBind{sock4: -1, sock6: -1} }
func NewDefaultBind() Bind     { return NewLinuxSocketBind() }

var _ Endpoint = (*LinuxSocketEndpoint)(nil)
var _ Bind = (*LinuxSocketBind)(nil)

func (*LinuxSocketBind) ParseEndpoint(s string) (Endpoint, error) {
	var end LinuxSocketEndpoint
	addr, err := parseEndpoint(s)
	if err != nil {
		return nil, err
	}

	ipv4 := addr.IP.To4()
	if ipv4 != nil {
		dst := end.dst4()
		end.isV6 = false
		dst.Port = addr.Port
		copy(dst.Addr[:], ipv4)
		end.ClearSrc()
		return &end, nil
	}

	ipv6 := addr.IP.To16()
	if ipv6 != nil {
		zone, err := zoneToUint32(addr.Zone)
		if err != nil {
			return nil, err
		}
		dst := end.dst6()
		end.isV6 = true
		dst.Port = addr.Port
		dst.ZoneId = zone
		copy(dst.Addr[:], ipv6[:])
		end.ClearSrc()
		return &end, nil
	}

	return nil, errors.New("invalid IP address")
}

func (bind *LinuxSocketBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()

	var err error
	var newPort uint16
	var tries int

	if bind.sock4 != -1 || bind.sock6 != -1 {
		return nil, 0, ErrBindAlreadyOpen
	}

	originalPort := port

again:
	port = originalPort
	var sock4, sock6 int
	// Attempt ipv6 bind, update port if successful.
	sock6, newPort, err = create6(port)
	if err != nil {
		if !errors.Is(err, syscall.EAFNOSUPPORT) {
			return nil, 0, err
		}
	} else {
		port = newPort
	}

	// Attempt ipv4 bind, update port if successful.
	sock4, newPort, err = create4(port)
	if err != nil {
		if originalPort == 0 && errors.Is(err, syscall.EADDRINUSE) && tries < 100 {
			unix.Close(sock6)
			tries++
			goto again
		}
		if !errors.Is(err, syscall.EAFNOSUPPORT) {
			unix.Close(sock6)
			return nil, 0, err
		}
	} else {
		port = newPort
	}

	var fns []ReceiveFunc
	if sock4 != -1 {
		bind.sock4 = sock4
		fns = append(fns, bind.receiveIPv4)
	}
	if sock6 != -1 {
		bind.sock6 = sock6
		fns = append(fns, bind.receiveIPv6)
	}
	if len(fns) == 0 {
		return nil, 0, syscall.EAFNOSUPPORT
	}
	return fns, port, nil
}

func (bind *LinuxSocketBind) SetMark(value uint32) error {
	bind.mu.RLock()
	defer bind.mu.RUnlock()

	if bind.sock6 != -1 {
		err := unix.SetsockoptInt(
			bind.sock6,
			unix.SOL_SOCKET,
			unix.SO_MARK,
			int(value),
		)

		if err != nil {
			return err
		}
	}

	if bind.sock4 != -1 {
		err := unix.SetsockoptInt(
			bind.sock4,
			unix.SOL_SOCKET,
			unix.SO_MARK,
			int(value),
		)

		if err != nil {
			return err
		}
	}

	return nil
}

func (bind *LinuxSocketBind) Close() error {
	// Take a readlock to shut down the sockets...
	bind.mu.RLock()
	if bind.sock6 != -1 {
		unix.Shutdown(bind.sock6, unix.SHUT_RDWR)
	}
	if bind.sock4 != -1 {
		unix.Shutdown(bind.sock4, unix.SHUT_RDWR)
	}
	bind.mu.RUnlock()
	// ...and a write lock to close the fd.
	// This ensures that no one else is using the fd.
	bind.mu.Lock()
	defer bind.mu.Unlock()
	var err1, err2 error
	if bind.sock6 != -1 {
		err1 = unix.Close(bind.sock6)
		bind.sock6 = -1
	}
	if bind.sock4 != -1 {
		err2 = unix.Close(bind.sock4)
		bind.sock4 = -1
	}

	if err1 != nil {
		return err1
	}
	return err2
}

func (bind *LinuxSocketBind) receiveIPv4(buf []byte) (int, Endpoint, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if bind.sock4 == -1 {
		return 0, nil, net.ErrClosed
	}
	var end LinuxSocketEndpoint
	n, err := receive4(bind.sock4, buf, &end)
	return n, &end, err
}

func (bind *LinuxSocketBind) receiveIPv6(buf []byte) (int, Endpoint, error) {
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if bind.sock6 == -1 {
		return 0, nil, net.ErrClosed
	}
	var end LinuxSocketEndpoint
	n, err := receive6(bind.sock6, buf, &end)
	return n, &end, err
}

func (bind *LinuxSocketBind) Send(buff []byte, end Endpoint) error {
	nend, ok := end.(*LinuxSocketEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}
	bind.mu.RLock()
	defer bind.mu.RUnlock()
	if !nend.isV6 {
		if bind.sock4 == -1 {
			return net.ErrClosed
		}
		return send4(bind.sock4, nend, buff)
	} else {
		if bind.sock6 == -1 {
			return net.ErrClosed
		}
		return send6(bind.sock6, nend, buff)
	}
}

func (end *LinuxSocketEndpoint) SrcIP() net.IP {
	if !end.isV6 {
		return net.IPv4(
			end.src4().Src[0],
			end.src4().Src[1],
			end.src4().Src[2],
			end.src4().Src[3],
		)
	} else {
		return end.src6().src[:]
	}
}

func (end *LinuxSocketEndpoint) DstIP() net.IP {
	if !end.isV6 {
		return net.IPv4(
			end.dst4().Addr[0],
			end.dst4().Addr[1],
			end.dst4().Addr[2],
			end.dst4().Addr[3],
		)
	} else {
		return end.dst6().Addr[:]
	}
}

func (end *LinuxSocketEndpoint) DstToBytes() []byte {
	if !end.isV6 {
		return (*[unsafe.Offsetof(end.dst4().Addr) + unsafe.Sizeof(end.dst4().Addr)]byte)(unsafe.Pointer(end.dst4()))[:]
	} else {
		return (*[unsafe.Offsetof(end.dst6().Addr) + unsafe.Sizeof(end.dst6().Addr)]byte)(unsafe.Pointer(end.dst6()))[:]
	}
}

func (end *LinuxSocketEndpoint) SrcToString() string {
	return end.SrcIP().String()
}

func (end *LinuxSocketEndpoint) DstToString() string {
	var udpAddr net.UDPAddr
	udpAddr.IP = end.DstIP()
	if !end.isV6 {
		udpAddr.Port = end.dst4().Port
	} else {
		udpAddr.Port = end.dst6().Port
	}
	return udpAddr.String()
}

func (end *LinuxSocketEndpoint) ClearDst() {
	for i := range end.dst {
		end.dst[i] = 0
	}
}

func (end *LinuxSocketEndpoint) ClearSrc() {
	for i := range end.src {
		end.src[i] = 0
	}
}

func zoneToUint32(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if intr, err := net.InterfaceByName(zone); err == nil {
		return uint32(intr.Index), nil
	}
	n, err := strconv.ParseUint(zone, 10, 32)
	return uint32(n), err
}

func create4(port uint16) (int, uint16, error) {

	// create socket

	fd, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return -1, 0, err
	}

	addr := unix.SockaddrInet4{
		Port: int(port),
	}

	// set sockopts and bind

	if err := func() error {
		if err := unix.SetsockoptInt(
			fd,
			unix.IPPROTO_IP,
			unix.IP_PKTINFO,
			1,
		); err != nil {
			return err
		}

		return unix.Bind(fd, &addr)
	}(); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}

	sa, err := unix.Getsockname(fd)
	if err == nil {
		addr.Port = sa.(*unix.SockaddrInet4).Port
	}

	return fd, uint16(addr.Port), err
}

func create6(port uint16) (int, uint16, error) {

	// create socket

	fd, err := unix.Socket(
		unix.AF_INET6,
		unix.SOCK_DGRAM,
		0,
	)

	if err != nil {
		return -1, 0, err
	}

	// set sockopts and bind

	addr := unix.SockaddrInet6{
		Port: int(port),
	}

	if err := func() error {
		if err := unix.SetsockoptInt(
			fd,
			unix.IPPROTO_IPV6,
			unix.IPV6_RECVPKTINFO,
			1,
		); err != nil {
			return err
		}

		if err := unix.SetsockoptInt(
			fd,
			unix.IPPROTO_IPV6,
			unix.IPV6_V6ONLY,
			1,
		); err != nil {
			return err
		}

		return unix.Bind(fd, &addr)

	}(); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}

	sa, err := unix.Getsockname(fd)
	if err == nil {
		addr.Port = sa.(*unix.SockaddrInet6).Port
	}

	return fd, uint16(addr.Port), err
}

func send4(sock int, end *LinuxSocketEndpoint, buff []byte) error {

	// construct message header

	cmsg := struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet4Pktinfo
	}{
		unix.Cmsghdr{
			Level: unix.IPPROTO_IP,
			Type:  unix.IP_PKTINFO,
			Len:   unix.SizeofInet4Pktinfo + unix.SizeofCmsghdr,
		},
		unix.Inet4Pktinfo{
			Spec_dst: end.src4().Src,
			Ifindex:  end.src4().Ifindex,
		},
	}

	end.mu.Lock()
	_, err := unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst4(), 0)
	end.mu.Unlock()

	if err == nil {
		return nil
	}

	// clear src and retry

	if err == unix.EINVAL {
		end.ClearSrc()
		cmsg.pktinfo = unix.Inet4Pktinfo{}
		end.mu.Lock()
		_, err = unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst4(), 0)
		end.mu.Unlock()
	}

	return err
}

func send6(sock int, end *LinuxSocketEndpoint, buff []byte) error {

	// construct message header

	cmsg := struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet6Pktinfo
	}{
		unix.Cmsghdr{
			Level: unix.IPPROTO_IPV6,
			Type:  unix.IPV6_PKTINFO,
			Len:   unix.SizeofInet6Pktinfo + unix.SizeofCmsghdr,
		},
		unix.Inet6Pktinfo{
			Addr:    end.src6().src,
			Ifindex: end.dst6().ZoneId,
		},
	}

	if cmsg.pktinfo.Addr == [16]byte{} {
		cmsg.pktinfo.Ifindex = 0
	}

	end.mu.Lock()
	_, err := unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst6(), 0)
	end.mu.Unlock()

	if err == nil {
		return nil
	}

	// clear src and retry

	if err == unix.EINVAL {
		end.ClearSrc()
		cmsg.pktinfo = unix.Inet6Pktinfo{}
		end.mu.Lock()
		_, err = unix.SendmsgN(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], end.dst6(), 0)
		end.mu.Unlock()
	}

	return err
}

func receive4(sock int, buff []byte, end *LinuxSocketEndpoint) (int, error) {

	// construct message header

	var cmsg struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet4Pktinfo
	}

	size, _, _, newDst, err := unix.Recvmsg(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], 0)

	if err != nil {
		return 0, err
	}
	end.isV6 = false

	if newDst4, ok := newDst.(*unix.SockaddrInet4); ok {
		*end.dst4() = *newDst4
	}

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IP &&
		cmsg.cmsghdr.Type == unix.IP_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet4Pktinfo {
		end.src4().Src = cmsg.pktinfo.Spec_dst
		end.src4().Ifindex = cmsg.pktinfo.Ifindex
	}

	return size, nil
}

func receive6(sock int, buff []byte, end *LinuxSocketEndpoint) (int, error) {

	// construct message header

	var cmsg struct {
		cmsghdr unix.Cmsghdr
		pktinfo unix.Inet6Pktinfo
	}

	size, _, _, newDst, err := unix.Recvmsg(sock, buff, (*[unsafe.Sizeof(cmsg)]byte)(unsafe.Pointer(&cmsg))[:], 0)

	if err != nil {
		return 0, err
	}
	end.isV6 = true

	if newDst6, ok := newDst.(*unix.SockaddrInet6); ok {
		*end.dst6() = *newDst6
	}

	// update source cache

	if cmsg.cmsghdr.Level == unix.IPPROTO_IPV6 &&
		cmsg.cmsghdr.Type == unix.IPV6_PKTINFO &&
		cmsg.cmsghdr.Len >= unix.SizeofInet6Pktinfo {
		end.src6().src = cmsg.pktinfo.Addr
		end.dst6().ZoneId = cmsg.pktinfo.Ifindex
	}

	return size, nil
}
