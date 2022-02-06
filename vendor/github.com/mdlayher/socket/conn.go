package socket

import (
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A Conn is a low-level network connection which integrates with Go's runtime
// network poller to provide asynchronous I/O and deadline support.
type Conn struct {
	// Indicates whether or not Conn.Close has been called. Must be accessed
	// atomically. Atomics definitions must come first in the Conn struct.
	closed uint32

	// A unique name for the Conn which is also associated with derived file
	// descriptors such as those created by accept(2).
	name string

	// Provides access to the underlying file registered with the runtime
	// network poller, and arbitrary raw I/O calls.
	fd *os.File
	rc syscall.RawConn
}

// High-level methods which provide convenience over raw system calls.

// Close closes the underlying file descriptor for the Conn, which also causes
// all in-flight I/O operations to immediately unblock and return errors. Any
// subsequent uses of Conn will result in EBADF.
func (c *Conn) Close() error {
	// The caller has expressed an intent to close the socket, so immediately
	// increment s.closed to force further calls to result in EBADF before also
	// closing the file descriptor to unblock any outstanding operations.
	//
	// Because other operations simply check for s.closed != 0, we will permit
	// double Close, which would increment s.closed beyond 1.
	if atomic.AddUint32(&c.closed, 1) != 1 {
		// Multiple Close calls.
		return nil
	}

	return os.NewSyscallError("close", c.fd.Close())
}

// Read implements io.Reader by reading directly from the underlying file
// descriptor.
func (c *Conn) Read(b []byte) (int, error) { return c.fd.Read(b) }

// Write implements io.Writer by writing directly to the underlying file
// descriptor.
func (c *Conn) Write(b []byte) (int, error) { return c.fd.Write(b) }

// SetDeadline sets both the read and write deadlines associated with the Conn.
func (c *Conn) SetDeadline(t time.Time) error { return c.fd.SetDeadline(t) }

// SetReadDeadline sets the read deadline associated with the Conn.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.fd.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline associated with the Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.fd.SetWriteDeadline(t) }

// ReadBuffer gets the size of the operating system's receive buffer associated
// with the Conn.
func (c *Conn) ReadBuffer() (int, error) {
	return c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUF)
}

// WriteBuffer gets the size of the operating system's transmit buffer
// associated with the Conn.
func (c *Conn) WriteBuffer() (int, error) {
	return c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_SNDBUF)
}

// SetReadBuffer sets the size of the operating system's receive buffer
// associated with the Conn.
//
// When called with elevated privileges on Linux, the SO_RCVBUFFORCE option will
// be used to override operating system limits. Otherwise SO_RCVBUF is used
// (which obeys operating system limits).
func (c *Conn) SetReadBuffer(bytes int) error { return c.setReadBuffer(bytes) }

// SetWriteBuffer sets the size of the operating system's transmit buffer
// associated with the Conn.
//
// When called with elevated privileges on Linux, the SO_SNDBUFFORCE option will
// be used to override operating system limits. Otherwise SO_SNDBUF is used
// (which obeys operating system limits).
func (c *Conn) SetWriteBuffer(bytes int) error { return c.setWriteBuffer(bytes) }

// SyscallConn returns a raw network connection. This implements the
// syscall.Conn interface.
//
// SyscallConn is intended for advanced use cases, such as getting and setting
// arbitrary socket options using the socket's file descriptor. If possible,
// those operations should be performed using methods on Conn instead.
//
// Once invoked, it is the caller's responsibility to ensure that operations
// performed using Conn and the syscall.RawConn do not conflict with each other.
func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, os.NewSyscallError("syscallconn", unix.EBADF)
	}

	// TODO(mdlayher): mutex or similar to enforce syscall.RawConn contract of
	// FD remaining valid for duration of calls?
	return c.rc, nil
}

// Socket wraps the socket(2) system call to produce a Conn. domain, typ, and
// proto are passed directly to socket(2), and name should be a unique name for
// the socket type such as "netlink" or "vsock".
//
// If the operating system supports SOCK_CLOEXEC and SOCK_NONBLOCK, they are
// automatically applied to typ to mirror the standard library's socket flag
// behaviors.
func Socket(domain, typ, proto int, name string) (*Conn, error) {
	var (
		fd  int
		err error
	)

	for {
		fd, err = unix.Socket(domain, typ|socketFlags, proto)
		switch {
		case err == nil:
			// Some OSes already set CLOEXEC with typ.
			if !flagCLOEXEC {
				unix.CloseOnExec(fd)
			}

			// No error, prepare the Conn.
			return newConn(fd, name)
		case !ready(err):
			// System call interrupted or not ready, try again.
			continue
		case err == unix.EINVAL, err == unix.EPROTONOSUPPORT:
			// On Linux, SOCK_NONBLOCK and SOCK_CLOEXEC were introduced in
			// 2.6.27. On FreeBSD, both flags were introduced in FreeBSD 10.
			// EINVAL and EPROTONOSUPPORT check for earlier versions of these
			// OSes respectively.
			//
			// Mirror what the standard library does when creating file
			// descriptors: avoid racing a fork/exec with the creation of new
			// file descriptors, so that child processes do not inherit socket
			// file descriptors unexpectedly.
			//
			// For a more thorough explanation, see similar work in the Go tree:
			// func sysSocket in net/sock_cloexec.go, as well as the detailed
			// comment in syscall/exec_unix.go.
			syscall.ForkLock.RLock()
			fd, err = unix.Socket(domain, typ, proto)
			if err == nil {
				unix.CloseOnExec(fd)
			}
			syscall.ForkLock.RUnlock()

			return newConn(fd, name)
		default:
			// Unhandled error.
			return nil, os.NewSyscallError("socket", err)
		}
	}
}

// TODO(mdlayher): consider exporting newConn as New?

// newConn wraps an existing file descriptor to create a Conn. name should be a
// unique name for the socket type such as "netlink" or "vsock".
func newConn(fd int, name string) (*Conn, error) {
	// All Conn I/O is nonblocking for integration with Go's runtime network
	// poller. Depending on the OS this might already be set but it can't hurt
	// to set it again.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}

	// os.NewFile registers the non-blocking file descriptor with the runtime
	// poller, which is then used for most subsequent operations except those
	// that require raw I/O via SyscallConn.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(fd), name)
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	return &Conn{
		name: name,
		fd:   f,
		rc:   rc,
	}, nil
}

// Low-level methods which provide raw system call access.

// Accept wraps accept(2) or accept4(2) depending on the operating system, but
// returns a Conn for the accepted connection rather than a raw file descriptor.
//
// If the operating system supports accept4(2) (which allows flags),
// SOCK_CLOEXEC and SOCK_NONBLOCK are automatically applied to flags to mirror
// the standard library's socket flag behaviors.
//
// If the operating system only supports accept(2) (which does not allow flags)
// and flags is not zero, an error will be returned.
func (c *Conn) Accept(flags int) (*Conn, unix.Sockaddr, error) {
	var (
		nfd int
		sa  unix.Sockaddr
		err error
	)

	doErr := c.read(sysAccept, func(fd int) error {
		// Either accept(2) or accept4(2) depending on the OS.
		nfd, sa, err = accept(fd, flags|socketFlags)
		return err
	})
	if doErr != nil {
		return nil, nil, doErr
	}
	if err != nil {
		// sysAccept is either "accept" or "accept4" depending on the OS.
		return nil, nil, os.NewSyscallError(sysAccept, err)
	}

	// Successfully accepted a connection, wrap it in a Conn for use by the
	// caller.
	ac, err := newConn(nfd, c.name)
	if err != nil {
		return nil, nil, err
	}

	return ac, sa, nil
}

// Bind wraps bind(2).
func (c *Conn) Bind(sa unix.Sockaddr) error {
	const op = "bind"

	var err error
	doErr := c.control(op, func(fd int) error {
		err = unix.Bind(fd, sa)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// Connect wraps connect(2).
func (c *Conn) Connect(sa unix.Sockaddr) error {
	const op = "connect"

	var err error
	doErr := c.write(op, func(fd int) error {
		err = unix.Connect(fd, sa)
		return err
	})
	if doErr != nil {
		return doErr
	}

	if err == unix.EISCONN {
		// Darwin reports EISCONN if already connected, but the socket is
		// established and we don't need to report an error.
		return nil
	}

	return os.NewSyscallError(op, err)
}

// Getsockname wraps getsockname(2).
func (c *Conn) Getsockname() (unix.Sockaddr, error) {
	const op = "getsockname"

	var (
		sa  unix.Sockaddr
		err error
	)

	doErr := c.control(op, func(fd int) error {
		sa, err = unix.Getsockname(fd)
		return err
	})
	if doErr != nil {
		return nil, doErr
	}

	return sa, os.NewSyscallError(op, err)
}

// GetsockoptInt wraps getsockopt(2) for integer values.
func (c *Conn) GetsockoptInt(level, opt int) (int, error) {
	const op = "getsockopt"

	var (
		value int
		err   error
	)

	doErr := c.control(op, func(fd int) error {
		value, err = unix.GetsockoptInt(fd, level, opt)
		return err
	})
	if doErr != nil {
		return 0, doErr
	}

	return value, os.NewSyscallError(op, err)
}

// Listen wraps listen(2).
func (c *Conn) Listen(n int) error {
	const op = "listen"

	var err error
	doErr := c.control(op, func(fd int) error {
		err = unix.Listen(fd, n)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// Recvmsg wraps recvmsg(2).
func (c *Conn) Recvmsg(p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
	const op = "recvmsg"

	var (
		n, oobn, recvflags int
		from               unix.Sockaddr
		err                error
	)

	doErr := c.read(op, func(fd int) error {
		n, oobn, recvflags, from, err = unix.Recvmsg(fd, p, oob, flags)
		return err
	})
	if doErr != nil {
		return 0, 0, 0, nil, doErr
	}

	return n, oobn, recvflags, from, os.NewSyscallError(op, err)
}

// Recvfrom wraps recvfrom(2)
func (c *Conn) Recvfrom(p []byte, flags int) (int, unix.Sockaddr, error) {
	const op = "recvfrom"

	var (
		n    int
		addr unix.Sockaddr
		err  error
	)

	doErr := c.read(op, func(fd int) error {
		n, addr, err = unix.Recvfrom(fd, p, flags)
		return err
	})
	if doErr != nil {
		return 0, nil, doErr
	}

	return n, addr, os.NewSyscallError(op, err)
}

// Sendmsg wraps sendmsg(2).
func (c *Conn) Sendmsg(p, oob []byte, to unix.Sockaddr, flags int) error {
	const op = "sendmsg"

	var err error
	doErr := c.write(op, func(fd int) error {
		err = unix.Sendmsg(fd, p, oob, to, flags)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// Sendto wraps Sendto(2).
func (c *Conn) Sendto(b []byte, to unix.Sockaddr, flags int) error {
	const op = "sendto"

	var err error
	doErr := c.write(op, func(fd int) error {
		err = unix.Sendto(fd, b, flags, to)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// SetsockoptInt wraps setsockopt(2) for integer values.
func (c *Conn) SetsockoptInt(level, opt, value int) error {
	const op = "setsockopt"

	var err error
	doErr := c.control(op, func(fd int) error {
		err = unix.SetsockoptInt(fd, level, opt, value)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// Conn low-level read/write/control functions. These functions mirror the
// syscall.RawConn APIs but the input closures return errors rather than
// booleans. Any syscalls invoked within f should return their error to allow
// the Conn to check for readiness with the runtime network poller, or to retry
// operations which may have been interrupted by EINTR or similar.
//
// Note that errors from the input closure functions are not propagated to the
// error return values of read/write/control, and the caller is still
// responsible for error handling.

// read executes f, a read function, against the associated file descriptor.
// op is used to create an *os.SyscallError if the file descriptor is closed.
func (c *Conn) read(op string, f func(fd int) error) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return os.NewSyscallError(op, unix.EBADF)
	}

	return c.rc.Read(func(fd uintptr) bool {
		return ready(f(int(fd)))
	})
}

// write executes f, a write function, against the associated file descriptor.
// op is used to create an *os.SyscallError if the file descriptor is closed.
func (c *Conn) write(op string, f func(fd int) error) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return os.NewSyscallError(op, unix.EBADF)
	}

	return c.rc.Write(func(fd uintptr) bool {
		return ready(f(int(fd)))
	})
}

// control executes f, a control function, against the associated file
// descriptor. op is used to create an *os.SyscallError if the file descriptor
// is closed.
func (c *Conn) control(op string, f func(fd int) error) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return os.NewSyscallError(op, unix.EBADF)
	}

	return c.rc.Control(func(fd uintptr) {
		// Repeatedly attempt the syscall(s) invoked by f until completion is
		// indicated by the return value of ready.
		for {
			if ready(f(int(fd))) {
				return
			}
		}
	})
}

// ready indicates readiness based on the value of err.
func ready(err error) bool {
	// When a socket is in non-blocking mode, we might see EAGAIN or
	// EINPROGRESS. In that case, return false to let the poller wait for
	// readiness. See the source code for internal/poll.FD.RawRead for more
	// details.
	//
	// Starting in Go 1.14, goroutines are asynchronously preemptible. The 1.14
	// release notes indicate that applications should expect to see EINTR more
	// often on slow system calls (like recvmsg while waiting for input), so we
	// must handle that case as well.
	switch err {
	case unix.EAGAIN, unix.EINTR, unix.EINPROGRESS:
		// Not ready.
		return false
	default:
		// Ready regardless of whether there was an error or no error.
		return true
	}
}
