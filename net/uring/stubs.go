// +build !linux

package uring

import (
	"net"
	"os"
	"time"

	"inet.af/netaddr"
)

// This file contains stubs for platforms that are known at compile time not to support io_uring.

type UDPConn struct{}

func NewUDPConn(*net.UDPConn) (*UDPConn, error)                        { panic("io_uring unavailable") }
func (u *UDPConn) ReadFromNetaddr([]byte) (int, netaddr.IPPort, error) { panic("io_uring unavailable") }
func (u *UDPConn) Close() error                                        { panic("io_uring unavailable") }
func (c *UDPConn) ReadFrom([]byte) (int, net.Addr, error)              { panic("io_uring unavailable") }
func (u *UDPConn) WriteTo([]byte, net.Addr) (int, error)               { panic("io_uring unavailable") }
func (c *UDPConn) LocalAddr() net.Addr                                 { panic("io_uring unavailable") }
func (c *UDPConn) SetDeadline(time.Time) error                         { panic("io_uring unavailable") }
func (c *UDPConn) SetReadDeadline(time.Time) error                     { panic("io_uring unavailable") }
func (c *UDPConn) SetWriteDeadline(time.Time) error                    { panic("io_uring unavailable") }

type File struct{}

func NewFile(file *os.File) (*File, error) { panic("io_uring unavailable") }
func (u *File) Read([]byte) (int, error)   { panic("io_uring unavailable") }
func (u *File) Write([]byte) (int, error)  { panic("io_uring unavailable") }
func (u *File) Close() error               { panic("io_uring unavailable") }
