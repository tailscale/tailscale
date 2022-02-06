package memconn

import (
	"net"
	"sync"
	"time"
)

// Conn is an in-memory implementation of Golang's "net.Conn" interface.
type Conn struct {
	pipe

	laddr Addr
	raddr Addr

	// buf contains information about the connection's buffer state if
	// the connection is buffered. Otherwise this field is nil.
	buf *bufConn
}

type bufConn struct {
	// Please see the SetCopyOnWrite function for more information.
	cow bool

	// Please see the SetBufferSize function for more information.
	max uint64

	// cur is the amount of buffered, pending Write data
	cur uint64

	// cond is a condition used to wait when writing buffered data
	cond sync.Cond

	// mu is the mutex used by the condition. The mutex is exposed
	// directly in order to access RLock and RUnlock for getting the
	// buffer size.
	mu sync.RWMutex

	// errs is the error channel returned by the Errs() function and
	// used to report erros that occur as a result of buffered write
	// operations. If the pipe does not use buffered writes then this
	// field will always be nil.
	errs chan error

	// Please see the SetCloseTimeout function for more information.
	closeTimeout time.Duration
}

func makeNewConns(network string, laddr, raddr Addr) (*Conn, *Conn) {
	// This code is duplicated from the Pipe() function from the file
	// "memconn_pipe.go". The reason for the duplication is to optimize
	// the performance by removing the need to wrap the *pipe values as
	// interface{} objects out of the Pipe() function and assert them
	// back as *pipe* objects in this function.
	cb1 := make(chan []byte)
	cb2 := make(chan []byte)
	cn1 := make(chan int)
	cn2 := make(chan int)
	done1 := make(chan struct{})
	done2 := make(chan struct{})

	// Wrap the pipes with Conn to support:
	//
	//   * The correct address information for the functions LocalAddr()
	//     and RemoteAddr() return the
	//   * Errors returns from the internal pipe are checked and
	//     have their internal OpError addr information replaced with
	//     the correct address information.
	//   * A channel can be setup to cause the event of the Listener
	//     closing closes the remoteConn immediately.
	//   * Buffered writes
	local := &Conn{
		pipe: pipe{
			rdRx: cb1, rdTx: cn1,
			wrTx: cb2, wrRx: cn2,
			localDone: done1, remoteDone: done2,
			readDeadline:  makePipeDeadline(),
			writeDeadline: makePipeDeadline(),
		},
		laddr: laddr,
		raddr: raddr,
	}
	remote := &Conn{
		pipe: pipe{
			rdRx: cb2, rdTx: cn2,
			wrTx: cb1, wrRx: cn1,
			localDone: done2, remoteDone: done1,
			readDeadline:  makePipeDeadline(),
			writeDeadline: makePipeDeadline(),
		},
		laddr: raddr,
		raddr: laddr,
	}

	if laddr.Buffered() {
		local.buf = &bufConn{
			errs:         make(chan error),
			closeTimeout: 10 * time.Second,
		}
		local.buf.cond.L = &local.buf.mu
	}

	if raddr.Buffered() {
		remote.buf = &bufConn{
			errs:         make(chan error),
			closeTimeout: 10 * time.Second,
		}
		remote.buf.cond.L = &remote.buf.mu
	}

	return local, remote
}

// LocalBuffered returns a flag indicating whether or not the local side
// of the connection is buffered.
func (c *Conn) LocalBuffered() bool {
	return c.laddr.Buffered()
}

// RemoteBuffered returns a flag indicating whether or not the remote side
// of the connection is buffered.
func (c *Conn) RemoteBuffered() bool {
	return c.raddr.Buffered()
}

// BufferSize gets the number of bytes allowed to be queued for
// asynchrnous Write operations.
//
// Please note that this function will always return zero for unbuffered
// connections.
//
// Please see the function SetBufferSize for more information.
func (c *Conn) BufferSize() uint64 {
	if c.laddr.Buffered() {
		c.buf.mu.RLock()
		defer c.buf.mu.RUnlock()
		return c.buf.max
	}
	return 0
}

// SetBufferSize sets the number of bytes allowed to be queued for
// asynchronous Write operations. Once the amount of data pending a Write
// operation exceeds the specified size, subsequent Writes will
// block until the queued data no longer exceeds the allowed ceiling.
//
// A value of zero means no maximum is defined.
//
// If a Write operation's payload length exceeds the buffer size
// (except for zero) then the Write operation is handled synchronously.
//
// Please note that setting the buffer size has no effect on unbuffered
// connections.
func (c *Conn) SetBufferSize(i uint64) {
	if c.laddr.Buffered() {
		c.buf.cond.L.Lock()
		defer c.buf.cond.L.Unlock()
		c.buf.max = i
	}
}

// CloseTimeout gets the time.Duration value used when closing buffered
// connections.
//
// Please note that this function will always return zero for
// unbuffered connections.
//
// Please see the function SetCloseTimeout for more information.
func (c *Conn) CloseTimeout() time.Duration {
	if c.laddr.Buffered() {
		c.buf.mu.RLock()
		defer c.buf.mu.RUnlock()
		return c.buf.closeTimeout
	}
	return 0
}

// SetCloseTimeout sets a time.Duration value used by the Close function
// to determine the amount of time to wait for pending, buffered Writes
// to complete before closing the connection.
//
// The default timeout value is 10 seconds. A zero value does not
// mean there is no timeout, rather it means the timeout is immediate.
//
// Please note that setting this value has no effect on unbuffered
// connections.
func (c *Conn) SetCloseTimeout(duration time.Duration) {
	if c.laddr.Buffered() {
		c.buf.cond.L.Lock()
		defer c.buf.cond.L.Unlock()
		c.buf.closeTimeout = duration
	}
}

// CopyOnWrite gets a flag indicating whether or not copy-on-write is
// enabled for this connection.
//
// Please note that this function will always return false for
// unbuffered connections.
//
// Please see the function SetCopyOnWrite for more information.
func (c *Conn) CopyOnWrite() bool {
	if c.laddr.Buffered() {
		c.buf.mu.RLock()
		defer c.buf.mu.RUnlock()
		return c.buf.cow
	}
	return false
}

// SetCopyOnWrite sets a flag indicating whether or not copy-on-write
// is enabled for this connection.
//
// When a connection is buffered, data submitted to a Write operation
// is processed in a goroutine and the function returns control to the
// caller immediately. Because of this, it's possible to modify the
// data provided to the Write function before or during the actual
// Write operation. Enabling copy-on-write causes the payload to be
// copied to a new buffer before control is returned to the caller.
//
// Please note that enabling copy-on-write will double the amount of
// memory required for all Write operations.
//
// Please note that enabling copy-on-write has no effect on unbuffered
// connections.
func (c *Conn) SetCopyOnWrite(enabled bool) {
	if c.laddr.Buffered() {
		c.buf.cond.L.Lock()
		defer c.buf.cond.L.Unlock()
		c.buf.cow = enabled
	}
}

// LocalAddr implements the net.Conn LocalAddr method.
func (c *Conn) LocalAddr() net.Addr {
	return c.laddr
}

// RemoteAddr implements the net.Conn RemoteAddr method.
func (c *Conn) RemoteAddr() net.Addr {
	return c.raddr
}

// Close implements the net.Conn Close method.
func (c *Conn) Close() error {
	c.pipe.once.Do(func() {

		// Buffered connections will attempt to wait until all
		// pending Writes are completed, until the specified
		// timeout value has elapsed, or until the remote side
		// of the connection is closed.
		if c.laddr.Buffered() {
			c.buf.mu.RLock()
			timeout := c.buf.closeTimeout
			c.buf.mu.RUnlock()

			// Set up a channel that is closed when the specified
			// timer elapses.
			timeoutDone := make(chan struct{})
			if timeout == 0 {
				close(timeoutDone)
			} else {
				time.AfterFunc(timeout, func() { close(timeoutDone) })
			}

			// Set up a channel that is closed when the number of
			// pending bytes is zero.
			writesDone := make(chan struct{})
			go func() {
				c.buf.cond.L.Lock()
				for c.buf.cur > 0 {
					c.buf.cond.Wait()
				}
				close(writesDone)
				c.buf.cond.L.Unlock()
			}()

			// Wait to close the connection.
			select {
			case <-writesDone:
			case <-timeoutDone:
			case <-c.pipe.remoteDone:
			}
		}

		close(c.pipe.localDone)
	})
	return nil
}

// Errs returns a channel that receives errors that may occur as the
// result of buffered write operations.
//
// This function will always return nil for unbuffered connections.
//
// Please note that the channel returned by this function is not closed
// when the connection is closed. This is because errors may continue
// to be sent over this channel as the result of asynchronous writes
// occurring after the connection is closed. Therefore this channel
// should not be used to determine when the connection is closed.
func (c *Conn) Errs() <-chan error {
	return c.buf.errs
}

// Read implements the net.Conn Read method.
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.pipe.Read(b)
	if err != nil {
		if e, ok := err.(*net.OpError); ok {
			e.Addr = c.raddr
			e.Source = c.laddr
			return n, e
		}
		return n, &net.OpError{
			Op:     "read",
			Addr:   c.raddr,
			Source: c.laddr,
			Net:    c.raddr.Network(),
			Err:    err,
		}
	}
	return n, nil
}

// Write implements the net.Conn Write method.
func (c *Conn) Write(b []byte) (int, error) {
	if c.laddr.Buffered() {
		return c.writeAsync(b)
	}
	return c.writeSync(b)
}

func (c *Conn) writeSync(b []byte) (int, error) {
	n, err := c.pipe.Write(b)
	if err != nil {
		if e, ok := err.(*net.OpError); ok {
			e.Addr = c.raddr
			e.Source = c.laddr
			return n, e
		}
		return n, &net.OpError{
			Op:     "write",
			Addr:   c.raddr,
			Source: c.laddr,
			Net:    c.raddr.Network(),
			Err:    err,
		}
	}
	return n, nil
}

// writeAsync performs the Write operation in a goroutine. This
// behavior means the Write operation is not blocking, but also means
// that when Write operations fail the associated error is not returned
// from this function.
func (c *Conn) writeAsync(b []byte) (int, error) {
	// Perform a synchronous Write if the connection has a non-zero
	// value for the maximum allowed buffer size and if the size of
	// the payload exceeds that maximum value.
	if c.buf.max > 0 && uint64(len(b)) > c.buf.max {
		return c.writeSync(b)
	}

	// Block the operation from proceeding until there is available
	// buffer space.
	c.buf.cond.L.Lock()
	for c.buf.max > 0 && uint64(len(b))+c.buf.cur > c.buf.max {
		c.buf.cond.Wait()
	}

	// Copy the buffer if the connection uses copy-on-write.
	cb := b
	if c.buf.cow {
		cb = make([]byte, len(b))
		copy(cb, b)
	}

	// Update the amount of active data being written.
	c.buf.cur = c.buf.cur + uint64(len(cb))

	c.buf.cond.L.Unlock()

	go func() {
		if _, err := c.writeSync(cb); err != nil {
			go func() { c.buf.errs <- err }()
		}

		// Decrement the enqueued buffer size and signal a blocked
		// goroutine that it may proceed
		c.buf.cond.L.Lock()
		c.buf.cur = c.buf.cur - uint64(len(cb))
		c.buf.cond.L.Unlock()
		c.buf.cond.Signal()
	}()
	return len(cb), nil
}

// SetReadDeadline implements the net.Conn SetReadDeadline method.
func (c *Conn) SetReadDeadline(t time.Time) error {
	if err := c.pipe.SetReadDeadline(t); err != nil {
		if e, ok := err.(*net.OpError); ok {
			e.Addr = c.laddr
			e.Source = c.laddr
			return e
		}
		return &net.OpError{
			Op:     "setReadDeadline",
			Addr:   c.laddr,
			Source: c.laddr,
			Net:    c.laddr.Network(),
			Err:    err,
		}
	}
	return nil
}

// SetWriteDeadline implements the net.Conn SetWriteDeadline method.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	if err := c.pipe.SetWriteDeadline(t); err != nil {
		if e, ok := err.(*net.OpError); ok {
			e.Addr = c.laddr
			e.Source = c.laddr
			return e
		}
		return &net.OpError{
			Op:     "setWriteDeadline",
			Addr:   c.laddr,
			Source: c.laddr,
			Net:    c.laddr.Network(),
			Err:    err,
		}
	}
	return nil
}
