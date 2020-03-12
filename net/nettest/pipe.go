// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nettest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"time"
)

const debugPipe = false

// Pipe implements an in-memory FIFO with timeouts.
type Pipe struct {
	name   string
	maxBuf int
	rCh    chan struct{}
	wCh    chan struct{}

	mu               sync.Mutex
	closed           bool
	blocked          bool
	buf              []byte
	readTimeout      time.Time
	writeTimeout     time.Time
	cancelReadTimer  func()
	cancelWriteTimer func()
}

// NewPipe creates a Pipe with a buffer size fixed at maxBuf.
func NewPipe(name string, maxBuf int) *Pipe {
	return &Pipe{
		name:   name,
		maxBuf: maxBuf,
		rCh:    make(chan struct{}, 1),
		wCh:    make(chan struct{}, 1),
	}
}

var (
	ErrTimeout      = errors.New("timeout")
	ErrReadTimeout  = fmt.Errorf("read %w", ErrTimeout)
	ErrWriteTimeout = fmt.Errorf("write %w", ErrTimeout)
)

// Read implements io.Reader.
func (p *Pipe) Read(b []byte) (n int, err error) {
	if debugPipe {
		orig := b
		defer func() {
			log.Printf("Pipe(%q).Read( %q) n=%d, err=%v", p.name, string(orig[:n]), n, err)
		}()
	}
	for {
		p.mu.Lock()
		closed := p.closed
		timedout := !p.readTimeout.IsZero() && time.Now().After(p.readTimeout)
		blocked := p.blocked
		if !closed && !timedout && len(p.buf) > 0 {
			n2 := copy(b, p.buf)
			p.buf = p.buf[n2:]
			b = b[n2:]
			n += n2
		}
		p.mu.Unlock()

		if closed {
			return 0, fmt.Errorf("nettest.Pipe(%q): closed: %w", p.name, io.EOF)
		}
		if timedout {
			return 0, fmt.Errorf("nettest.Pipe(%q): %w", p.name, ErrReadTimeout)
		}
		if blocked {
			<-p.rCh
			continue
		}
		if n > 0 {
			p.signalWrite()
			return n, nil
		}
		<-p.rCh
	}
}

// Write implements io.Writer.
func (p *Pipe) Write(b []byte) (n int, err error) {
	if debugPipe {
		orig := b
		defer func() {
			log.Printf("Pipe(%q).Write(%q) n=%d, err=%v", p.name, string(orig), n, err)
		}()
	}
	for {
		p.mu.Lock()
		closed := p.closed
		timedout := !p.writeTimeout.IsZero() && time.Now().After(p.writeTimeout)
		blocked := p.blocked
		if !closed && !timedout {
			n2 := len(b)
			if limit := p.maxBuf - len(p.buf); limit < n2 {
				n2 = limit
			}
			p.buf = append(p.buf, b[:n2]...)
			b = b[n2:]
			n += n2
		}
		p.mu.Unlock()

		if closed {
			return n, fmt.Errorf("nettest.Pipe(%q): closed: %w", p.name, io.EOF)
		}
		if timedout {
			return n, fmt.Errorf("nettest.Pipe(%q): %w", p.name, ErrWriteTimeout)
		}
		if blocked {
			<-p.wCh
			continue
		}
		if n > 0 {
			p.signalRead()
		}
		if len(b) == 0 {
			return n, nil
		}
		<-p.wCh
	}
}

// Close implements io.Closer.
func (p *Pipe) Close() error {
	p.mu.Lock()
	closed := p.closed
	p.closed = true
	if p.cancelWriteTimer != nil {
		p.cancelWriteTimer()
		p.cancelWriteTimer = nil
	}
	if p.cancelReadTimer != nil {
		p.cancelReadTimer()
		p.cancelReadTimer = nil
	}
	p.mu.Unlock()

	if closed {
		return fmt.Errorf("nettest.Pipe(%q).Close: already closed", p.name)
	}

	p.signalRead()
	p.signalWrite()
	return nil
}

// SetReadDeadline sets the deadline for future Read calls.
func (p *Pipe) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readTimeout = t
	if p.cancelReadTimer != nil {
		p.cancelReadTimer()
		p.cancelReadTimer = nil
	}
	if d := time.Until(t); !t.IsZero() && d > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		p.cancelReadTimer = cancel
		go func() {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				p.signalRead()
			case <-ctx.Done():
			}
		}()
	}
	p.mu.Unlock()

	p.signalRead()
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
func (p *Pipe) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeTimeout = t
	if p.cancelWriteTimer != nil {
		p.cancelWriteTimer()
		p.cancelWriteTimer = nil
	}
	if d := time.Until(t); !t.IsZero() && d > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		p.cancelWriteTimer = cancel
		go func() {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				p.signalWrite()
			case <-ctx.Done():
			}
		}()
	}
	p.mu.Unlock()

	p.signalWrite()
	return nil
}

func (p *Pipe) Block() error {
	p.mu.Lock()
	closed := p.closed
	blocked := p.blocked
	p.blocked = true
	p.mu.Unlock()

	if closed {
		return fmt.Errorf("nettest.Pipe(%q).Block: closed", p.name)
	}
	if blocked {
		return fmt.Errorf("nettest.Pipe(%q).Block: already blocked", p.name)
	}
	p.signalRead()
	p.signalWrite()
	return nil
}

func (p *Pipe) Unblock() error {
	p.mu.Lock()
	closed := p.closed
	blocked := p.blocked
	p.blocked = false
	p.mu.Unlock()

	if closed {
		return fmt.Errorf("nettest.Pipe(%q).Block: closed", p.name)
	}
	if !blocked {
		return fmt.Errorf("nettest.Pipe(%q).Block: already unblocked", p.name)
	}
	p.signalRead()
	p.signalWrite()
	return nil
}

func (p *Pipe) signalRead() {
	select {
	case p.rCh <- struct{}{}:
	default:
	}
}

func (p *Pipe) signalWrite() {
	select {
	case p.wCh <- struct{}{}:
	default:
	}
}
