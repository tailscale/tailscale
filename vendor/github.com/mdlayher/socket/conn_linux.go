//go:build linux
// +build linux

package socket

import (
	"os"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// SetBPF attaches an assembled BPF program to a Conn.
func (c *Conn) SetBPF(filter []bpf.RawInstruction) error {
	// We can't point to the first instruction in the array if no instructions
	// are present.
	if len(filter) == 0 {
		return os.NewSyscallError("setsockopt", unix.EINVAL)
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	return c.SetsockoptSockFprog(unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
}

// RemoveBPF removes a BPF filter from a Conn.
func (c *Conn) RemoveBPF() error {
	// 0 argument is ignored.
	return c.SetsockoptInt(unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0)
}

// SetsockoptSockFprog wraps setsockopt(2) for unix.SockFprog values.
func (c *Conn) SetsockoptSockFprog(level, opt int, fprog *unix.SockFprog) error {
	const op = "setsockopt"

	var err error
	doErr := c.control(op, func(fd int) error {
		err = unix.SetsockoptSockFprog(fd, level, opt, fprog)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// GetSockoptTpacketStats wraps getsockopt(2) for getting TpacketStats
func (c *Conn) GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error) {
	const op = "getsockopt"

	var (
		stats *unix.TpacketStats
		err   error
	)

	doErr := c.control(op, func(fd int) error {
		stats, err = unix.GetsockoptTpacketStats(fd, level, name)
		return err
	})
	if doErr != nil {
		return stats, doErr
	}
	return stats, os.NewSyscallError(op, err)
}

// GetSockoptTpacketStatsV3 wraps getsockopt(2) for getting TpacketStatsV3
func (c *Conn) GetSockoptTpacketStatsV3(level, name int) (*unix.TpacketStatsV3, error) {
	const op = "getsockopt"

	var (
		stats *unix.TpacketStatsV3
		err   error
	)

	doErr := c.control(op, func(fd int) error {
		stats, err = unix.GetsockoptTpacketStatsV3(fd, level, name)
		return err
	})
	if doErr != nil {
		return stats, doErr
	}
	return stats, os.NewSyscallError(op, err)
}
