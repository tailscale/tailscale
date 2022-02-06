/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	_TUNSIFHEAD = 0x80047460
	_TUNSIFMODE = 0x8004745e
	_TUNGIFNAME = 0x4020745d
	_TUNSIFPID  = 0x2000745f

	_SIOCGIFINFO_IN6        = 0xc048696c
	_SIOCSIFINFO_IN6        = 0xc048696d
	_ND6_IFF_AUTO_LINKLOCAL = 0x20
	_ND6_IFF_NO_DAD         = 0x100
)

// Iface requests with just the name
type ifreqName struct {
	Name [unix.IFNAMSIZ]byte
	_    [16]byte
}

// Iface requests with a pointer
type ifreqPtr struct {
	Name [unix.IFNAMSIZ]byte
	Data uintptr
	_    [16 - unsafe.Sizeof(uintptr(0))]byte
}

// Iface requests with MTU
type ifreqMtu struct {
	Name [unix.IFNAMSIZ]byte
	MTU  uint32
	_    [12]byte
}

// ND6 flag manipulation
type nd6Req struct {
	Name          [unix.IFNAMSIZ]byte
	Linkmtu       uint32
	Maxmtu        uint32
	Basereachable uint32
	Reachable     uint32
	Retrans       uint32
	Flags         uint32
	Recalctm      int
	Chlim         uint8
	Initialized   uint8
	Randomseed0   [8]byte
	Randomseed1   [8]byte
	Randomid      [8]byte
}

type NativeTun struct {
	name        string
	tunFile     *os.File
	events      chan Event
	errors      chan error
	routeSocket int
	closeOnce   sync.Once
}

func (tun *NativeTun) routineRouteListener(tunIfindex int) {
	var (
		statusUp  bool
		statusMTU int
	)

	defer close(tun.events)

	data := make([]byte, os.Getpagesize())
	for {
	retry:
		n, err := unix.Read(tun.routeSocket, data)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				goto retry
			}
			tun.errors <- err
			return
		}

		if n < 14 {
			continue
		}

		if data[3 /* type */] != unix.RTM_IFINFO {
			continue
		}
		ifindex := int(*(*uint16)(unsafe.Pointer(&data[12 /* ifindex */])))
		if ifindex != tunIfindex {
			continue
		}

		iface, err := net.InterfaceByIndex(ifindex)
		if err != nil {
			tun.errors <- err
			return
		}

		// Up / Down event
		up := (iface.Flags & net.FlagUp) != 0
		if up != statusUp && up {
			tun.events <- EventUp
		}
		if up != statusUp && !up {
			tun.events <- EventDown
		}
		statusUp = up

		// MTU changes
		if iface.MTU != statusMTU {
			tun.events <- EventMTUUpdate
		}
		statusMTU = iface.MTU
	}
}

func tunName(fd uintptr) (string, error) {
	var ifreq ifreqName
	_, _, err := unix.Syscall(unix.SYS_IOCTL, fd, _TUNGIFNAME, uintptr(unsafe.Pointer(&ifreq)))
	if err != 0 {
		return "", err
	}
	return unix.ByteSliceToString(ifreq.Name[:]), nil
}

// Destroy a named system interface
func tunDestroy(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr [32]byte
	copy(ifr[:], name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCIFDESTROY), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return fmt.Errorf("failed to destroy interface %s: %w", name, errno)
	}

	return nil
}

func CreateTUN(name string, mtu int) (Device, error) {
	if len(name) > unix.IFNAMSIZ-1 {
		return nil, errors.New("interface name too long")
	}

	// See if interface already exists
	iface, _ := net.InterfaceByName(name)
	if iface != nil {
		return nil, fmt.Errorf("interface %s already exists", name)
	}

	tunFile, err := os.OpenFile("/dev/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	tun := NativeTun{tunFile: tunFile}
	var assignedName string
	tun.operateOnFd(func(fd uintptr) {
		assignedName, err = tunName(fd)
	})
	if err != nil {
		tunFile.Close()
		return nil, err
	}

	// Enable ifhead mode, otherwise tun will complain if it gets a non-AF_INET packet
	ifheadmode := 1
	var errno syscall.Errno
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, _TUNSIFHEAD, uintptr(unsafe.Pointer(&ifheadmode)))
	})

	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to put into IFHEAD mode: %w", errno)
	}

	// Get out of PTP mode.
	ifflags := syscall.IFF_BROADCAST | syscall.IFF_MULTICAST
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(_TUNSIFMODE), uintptr(unsafe.Pointer(&ifflags)))
	})

	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to put into IFF_BROADCAST mode: %w", errno)
	}

	// Disable link-local v6, not just because WireGuard doesn't do that anyway, but
	// also because there are serious races with attaching and detaching LLv6 addresses
	// in relation to interface lifetime within the FreeBSD kernel.
	confd6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, err
	}
	defer unix.Close(confd6)
	var ndireq nd6Req
	copy(ndireq.Name[:], assignedName)
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(confd6), uintptr(_SIOCGIFINFO_IN6), uintptr(unsafe.Pointer(&ndireq)))
	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to get nd6 flags for %s: %w", assignedName, errno)
	}
	ndireq.Flags = ndireq.Flags &^ _ND6_IFF_AUTO_LINKLOCAL
	ndireq.Flags = ndireq.Flags | _ND6_IFF_NO_DAD
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(confd6), uintptr(_SIOCSIFINFO_IN6), uintptr(unsafe.Pointer(&ndireq)))
	if errno != 0 {
		tunFile.Close()
		tunDestroy(assignedName)
		return nil, fmt.Errorf("unable to set nd6 flags for %s: %w", assignedName, errno)
	}

	if name != "" {
		confd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			tunFile.Close()
			tunDestroy(assignedName)
			return nil, err
		}
		defer unix.Close(confd)
		var newnp [unix.IFNAMSIZ]byte
		copy(newnp[:], name)
		var ifr ifreqPtr
		copy(ifr.Name[:], assignedName)
		ifr.Data = uintptr(unsafe.Pointer(&newnp[0]))
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(confd), uintptr(unix.SIOCSIFNAME), uintptr(unsafe.Pointer(&ifr)))
		if errno != 0 {
			tunFile.Close()
			tunDestroy(assignedName)
			return nil, fmt.Errorf("Failed to rename %s to %s: %w", assignedName, name, errno)
		}
	}

	return CreateTUNFromFile(tunFile, mtu)
}

func CreateTUNFromFile(file *os.File, mtu int) (Device, error) {
	tun := &NativeTun{
		tunFile: file,
		events:  make(chan Event, 10),
		errors:  make(chan error, 1),
	}

	var errno syscall.Errno
	tun.operateOnFd(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, _TUNSIFPID, uintptr(0))
	})
	if errno != 0 {
		tun.tunFile.Close()
		return nil, fmt.Errorf("unable to become controlling TUN process: %w", errno)
	}

	name, err := tun.Name()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	tunIfindex, err := func() (int, error) {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return -1, err
		}
		return iface.Index, nil
	}()
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	tun.routeSocket, err = unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		tun.tunFile.Close()
		return nil, err
	}

	go tun.routineRouteListener(tunIfindex)

	err = tun.setMTU(mtu)
	if err != nil {
		tun.Close()
		return nil, err
	}

	return tun, nil
}

func (tun *NativeTun) Name() (string, error) {
	var name string
	var err error
	tun.operateOnFd(func(fd uintptr) {
		name, err = tunName(fd)
	})
	if err != nil {
		return "", err
	}
	tun.name = name
	return name, nil
}

func (tun *NativeTun) File() *os.File {
	return tun.tunFile
}

func (tun *NativeTun) Events() chan Event {
	return tun.events
}

func (tun *NativeTun) Read(buff []byte, offset int) (int, error) {
	select {
	case err := <-tun.errors:
		return 0, err
	default:
		buff := buff[offset-4:]
		n, err := tun.tunFile.Read(buff[:])
		if n < 4 {
			return 0, err
		}
		return n - 4, err
	}
}

func (tun *NativeTun) Write(buf []byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	buf = buf[offset-4:]
	if len(buf) < 5 {
		return 0, io.ErrShortBuffer
	}
	buf[0] = 0x00
	buf[1] = 0x00
	buf[2] = 0x00
	switch buf[4] >> 4 {
	case 4:
		buf[3] = unix.AF_INET
	case 6:
		buf[3] = unix.AF_INET6
	default:
		return 0, unix.EAFNOSUPPORT
	}
	return tun.tunFile.Write(buf)
}

func (tun *NativeTun) Flush() error {
	// TODO: can flushing be implemented by buffering and using sendmmsg?
	return nil
}

func (tun *NativeTun) Close() error {
	var err1, err2, err3 error
	tun.closeOnce.Do(func() {
		err1 = tun.tunFile.Close()
		err2 = tunDestroy(tun.name)
		if tun.routeSocket != -1 {
			unix.Shutdown(tun.routeSocket, unix.SHUT_RDWR)
			err3 = unix.Close(tun.routeSocket)
			tun.routeSocket = -1
		} else if tun.events != nil {
			close(tun.events)
		}
	})
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (tun *NativeTun) setMTU(n int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr ifreqMtu
	copy(ifr.Name[:], tun.name)
	ifr.MTU = uint32(n)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("failed to set MTU on %s: %w", tun.name, errno)
	}
	return nil
}

func (tun *NativeTun) MTU() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	var ifr ifreqMtu
	copy(ifr.Name[:], tun.name)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCGIFMTU), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return 0, fmt.Errorf("failed to get MTU on %s: %w", tun.name, errno)
	}
	return int(*(*int32)(unsafe.Pointer(&ifr.MTU))), nil
}
