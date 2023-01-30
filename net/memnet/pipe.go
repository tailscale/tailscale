// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package memnet

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"
)

const debugPipe = false

// Pipe implements an in-memory FIFO with timeouts.
type Pipe struct {
	name   string
	maxBuf int
	mu     sync.Mutex
	cnd    *sync.Cond

	blocked          bool
	closed           bool
	buf              bytes.Buffer
	readTimeout      time.Time
	writeTimeout     time.Time
	cancelReadTimer  func()
	cancelWriteTimer func()
}

// NewPipe creates a Pipe with a buffer size fixed at maxBuf.
func NewPipe(name string, maxBuf int) *Pipe {
	p := &Pipe{
		name:   name,
		maxBuf: maxBuf,
	}
	p.cnd = sync.NewCond(&p.mu)
	return p
}

// readOrBlock attempts to read from the buffer, if the buffer is empty and
// the connection hasn't been closed it will block until there is a change.
func (p *Pipe) readOrBlock(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.readTimeout.IsZero() && !time.Now().Before(p.readTimeout) {
		return 0, os.ErrDeadlineExceeded
	}
	if p.blocked {
		p.cnd.Wait()
		return 0, nil
	}

	n, err := p.buf.Read(b)
	// err will either be nil or io.EOF.
	if err == io.EOF {
		if p.closed {
			return n, err
		}
		// Wait for something to change.
		p.cnd.Wait()
	}
	return n, nil
}

// Read implements io.Reader.
// Once the buffer is drained (i.e. after Close), subsequent calls will
// return io.EOF.
func (p *Pipe) Read(b []byte) (n int, err error) {
	if debugPipe {
		orig := b
		defer func() {
			log.Printf("Pipe(%q).Read(%q) n=%d, err=%v", p.name, string(orig[:n]), n, err)
		}()
	}
	for n == 0 {
		n2, err := p.readOrBlock(b)
		if err != nil {
			return n2, err
		}
		n += n2
	}
	p.cnd.Signal()
	return n, nil
}

// writeOrBlock attempts to write to the buffer, if the buffer is full it will
// block until there is a change.
func (p *Pipe) writeOrBlock(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	if !p.writeTimeout.IsZero() && !time.Now().Before(p.writeTimeout) {
		return 0, os.ErrDeadlineExceeded
	}
	if p.blocked {
		p.cnd.Wait()
		return 0, nil
	}

	// Optimistically we want to write the entire slice.
	n := len(b)
	if limit := p.maxBuf - p.buf.Len(); limit < n {
		// However, we don't have enough capacity to write everything.
		n = limit
	}
	if n == 0 {
		// Wait for something to change.
		p.cnd.Wait()
		return 0, nil
	}

	p.buf.Write(b[:n])
	p.cnd.Signal()
	return n, nil
}

// Write implements io.Writer.
func (p *Pipe) Write(b []byte) (n int, err error) {
	if debugPipe {
		orig := b
		defer func() {
			log.Printf("Pipe(%q).Write(%q) n=%d, err=%v", p.name, string(orig), n, err)
		}()
	}
	for len(b) > 0 {
		n2, err := p.writeOrBlock(b)
		if err != nil {
			return n + n2, err
		}
		n += n2
		b = b[n2:]
	}
	return n, nil
}

// Close closes the pipe.
func (p *Pipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.blocked = false
	if p.cancelWriteTimer != nil {
		p.cancelWriteTimer()
		p.cancelWriteTimer = nil
	}
	if p.cancelReadTimer != nil {
		p.cancelReadTimer()
		p.cancelReadTimer = nil
	}
	p.cnd.Broadcast()

	return nil
}

func (p *Pipe) deadlineTimer(t time.Time) func() {
	if t.IsZero() {
		return nil
	}
	if t.Before(time.Now()) {
		p.cnd.Broadcast()
		return nil
	}
	ctx, cancel := context.WithDeadline(context.Background(), t)
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			p.cnd.Broadcast()
		}
	}()
	return cancel
}

// SetReadDeadline sets the deadline for future Read calls.
func (p *Pipe) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.readTimeout = t
	// If we already have a deadline, cancel it and create a new one.
	if p.cancelReadTimer != nil {
		p.cancelReadTimer()
		p.cancelReadTimer = nil
	}
	p.cancelReadTimer = p.deadlineTimer(t)
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
func (p *Pipe) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writeTimeout = t
	// If we already have a deadline, cancel it and create a new one.
	if p.cancelWriteTimer != nil {
		p.cancelWriteTimer()
		p.cancelWriteTimer = nil
	}
	p.cancelWriteTimer = p.deadlineTimer(t)
	return nil
}

// Block will cause all calls to Read and Write to block until they either
// timeout, are unblocked or the pipe is closed.
func (p *Pipe) Block() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	closed := p.closed
	blocked := p.blocked
	p.blocked = true

	if closed {
		return fmt.Errorf("memnet.Pipe(%q).Block: closed", p.name)
	}
	if blocked {
		return fmt.Errorf("memnet.Pipe(%q).Block: already blocked", p.name)
	}
	p.cnd.Broadcast()
	return nil
}

// Unblock will cause all blocked Read/Write calls to continue execution.
func (p *Pipe) Unblock() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	closed := p.closed
	blocked := p.blocked
	p.blocked = false

	if closed {
		return fmt.Errorf("memnet.Pipe(%q).Block: closed", p.name)
	}
	if !blocked {
		return fmt.Errorf("memnet.Pipe(%q).Block: already unblocked", p.name)
	}
	p.cnd.Broadcast()
	return nil
}
