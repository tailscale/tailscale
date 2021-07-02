// +build !linux

package uring

import (
	"net"
	"os"
	"time"

	"inet.af/netaddr"
)

func URingAvailable() bool { return false }

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
// TODO: Maybe combine the urings into a single uring with dispatch.
type UDPConn struct{}

func NewUDPConn(conn *net.UDPConn) (*UDPConn, error) { return nil, NotSupportedError }
func (c *UDPConn) LocalAddr() net.Addr               { panic("Not supported") }

func (u *UDPConn) Close() error { return NotSupportedError }
func (c *UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	err = NotSupportedError
	return
}
func (u *UDPConn) ReadFromNetaddr(buf []byte) (n int, addr netaddr.IPPort, err error) {
	err = NotSupportedError
	return
}
func (u *UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) { return 0, NotSupportedError }
func (c *UDPConn) SetDeadline(t time.Time) error                { return NotSupportedError }
func (c *UDPConn) SetReadDeadline(t time.Time) error            { return NotSupportedError }
func (c *UDPConn) SetWriteDeadline(t time.Time) error           { return NotSupportedError }

// A File is a write-only file fd manager.
// TODO: Support reads
// TODO: all the todos from UDPConn
type File struct{}

func NewFile(file *os.File) (*File, error)    { return nil, NotSupportedError }
func (u *File) Write(buf []byte) (int, error) { return 0, NotSupportedError }

// Read data into buf[offset:].
// We are allowed to write junk into buf[offset-4:offset].
func (u *File) Read(buf []byte) (n int, err error) { return 0, NotSupportedError }
