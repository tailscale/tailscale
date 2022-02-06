//go:build darwin || freebsd || openbsd

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"errors"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

type UAPIListener struct {
	listener net.Listener // unix socket listener
	connNew  chan net.Conn
	connErr  chan error
	kqueueFd int
	keventFd int
}

func (l *UAPIListener) Accept() (net.Conn, error) {
	for {
		select {
		case conn := <-l.connNew:
			return conn, nil

		case err := <-l.connErr:
			return nil, err
		}
	}
}

func (l *UAPIListener) Close() error {
	err1 := unix.Close(l.kqueueFd)
	err2 := unix.Close(l.keventFd)
	err3 := l.listener.Close()
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

func UAPIListen(name string, file *os.File) (net.Listener, error) {

	// wrap file in listener

	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(true)
	}

	socketPath := sockPath(name)

	// watch for deletion of socket

	uapi.kqueueFd, err = unix.Kqueue()
	if err != nil {
		return nil, err
	}
	uapi.keventFd, err = unix.Open(socketDirectory, unix.O_RDONLY, 0)
	if err != nil {
		unix.Close(uapi.kqueueFd)
		return nil, err
	}

	go func(l *UAPIListener) {
		event := unix.Kevent_t{
			Filter: unix.EVFILT_VNODE,
			Flags:  unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT,
			Fflags: unix.NOTE_WRITE,
		}
		// Allow this assignment to work with both the 32-bit and 64-bit version
		// of the above struct. If you know another way, please submit a patch.
		*(*uintptr)(unsafe.Pointer(&event.Ident)) = uintptr(uapi.keventFd)
		events := make([]unix.Kevent_t, 1)
		n := 1
		var kerr error
		for {
			// start with lstat to avoid race condition
			if _, err := os.Lstat(socketPath); os.IsNotExist(err) {
				l.connErr <- err
				return
			}
			if kerr != nil || n != 1 {
				if kerr != nil {
					l.connErr <- kerr
				} else {
					l.connErr <- errors.New("kqueue returned empty")
				}
				return
			}
			n, kerr = unix.Kevent(uapi.kqueueFd, []unix.Kevent_t{event}, events, nil)
		}
	}(uapi)

	// watch for new connections

	go func(l *UAPIListener) {
		for {
			conn, err := l.listener.Accept()
			if err != nil {
				l.connErr <- err
				break
			}
			l.connNew <- conn
		}
	}(uapi)

	return uapi, nil
}
