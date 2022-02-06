/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package ipc

import (
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// TODO: replace these with actual standard windows error numbers from the win package
const (
	IpcErrorIO        = -int64(5)
	IpcErrorProtocol  = -int64(71)
	IpcErrorInvalid   = -int64(22)
	IpcErrorPortInUse = -int64(98)
	IpcErrorUnknown   = -int64(55)
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
	return l.listener.Close()
}

func (l *UAPIListener) Addr() net.Addr {
	return l.listener.Addr()
}

var UAPISecurityDescriptor *windows.SECURITY_DESCRIPTOR

func init() {
	var err error
	UAPISecurityDescriptor, err = windows.SecurityDescriptorFromString("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNRNX;;;HI)")
	if err != nil {
		panic(err)
	}
}

func UAPIListen(name string) (net.Listener, error) {
	listener, err := (&namedpipe.ListenConfig{
		SecurityDescriptor: UAPISecurityDescriptor,
	}).Listen(`\\.\pipe\ProtectedPrefix\Administrators\WireGuard\` + name)
	if err != nil {
		return nil, err
	}

	uapi := &UAPIListener{
		listener: listener,
		connNew:  make(chan net.Conn, 1),
		connErr:  make(chan error, 1),
	}

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
