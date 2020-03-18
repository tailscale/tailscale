// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package nettest

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPipeHello(t *testing.T) {
	p := NewPipe("p1", 1<<16)
	msg := "Hello, World!"
	if n, err := p.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	} else if n != len(msg) {
		t.Errorf("p.Write(%q) n=%d, want %d", msg, n, len(msg))
	}
	b := make([]byte, len(msg))
	if n, err := p.Read(b); err != nil {
		t.Fatal(err)
	} else if n != len(b) {
		t.Errorf("p.Read(%q) n=%d, want %d", string(b[:n]), n, len(b))
	}
	if got := string(b); got != msg {
		t.Errorf("p.Read: %q, want %q", got, msg)
	}
}

func TestPipeTimeout(t *testing.T) {
	t.Run("write", func(t *testing.T) {
		p := NewPipe("p1", 1<<16)
		p.SetWriteDeadline(time.Now().Add(-1 * time.Second))
		n, err := p.Write([]byte{'h'})
		if err == nil || !errors.Is(err, ErrWriteTimeout) || !errors.Is(err, ErrTimeout) {
			t.Errorf("missing write timeout got err: %v", err)
		}
		if n != 0 {
			t.Errorf("n=%d on timeout", n)
		}
	})
	t.Run("read", func(t *testing.T) {
		p := NewPipe("p1", 1<<16)
		p.Write([]byte{'h'})

		p.SetReadDeadline(time.Now().Add(-1 * time.Second))
		b := make([]byte, 1)
		n, err := p.Read(b)
		if err == nil || !errors.Is(err, ErrReadTimeout) || !errors.Is(err, ErrTimeout) {
			t.Errorf("missing read timeout got err: %v", err)
		}
		if n != 0 {
			t.Errorf("n=%d on timeout", n)
		}
	})
	t.Run("block-write", func(t *testing.T) {
		p := NewPipe("p1", 1<<16)
		p.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
		if _, err := p.Write([]byte{'h'}); err != nil {
			t.Fatal(err)
		}
		if err := p.Block(); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Write([]byte{'h'}); err == nil || !errors.Is(err, ErrWriteTimeout) {
			t.Fatalf("want write timeout got: %v", err)
		}
	})
	t.Run("block-read", func(t *testing.T) {
		p := NewPipe("p1", 1<<16)
		p.Write([]byte{'h', 'i'})
		p.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		b := make([]byte, 1)
		if _, err := p.Read(b); err != nil {
			t.Fatal(err)
		}
		if err := p.Block(); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Read(b); err == nil || !errors.Is(err, ErrReadTimeout) {
			t.Fatalf("want read timeout got: %v", err)
		}
	})

}

func TestLimit(t *testing.T) {
	p := NewPipe("p1", 1)
	errCh := make(chan error)
	go func() {
		n, err := p.Write([]byte{'a', 'b', 'c'})
		if err != nil {
			errCh <- err
		} else if n != 3 {
			errCh <- fmt.Errorf("p.Write n=%d, want 3", n)
		} else {
			errCh <- nil
		}
	}()
	b := make([]byte, 3)

	if n, err := p.Read(b); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("Read(%q): n=%d want 1", string(b), n)
	}
	if n, err := p.Read(b); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("Read(%q): n=%d want 1", string(b), n)
	}
	if n, err := p.Read(b); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("Read(%q): n=%d want 1", string(b), n)
	}
}
