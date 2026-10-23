// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/health"
	"tailscale.com/types/nettype"
	"tailscale.com/util/eventbus"
)

// readResult is one scripted result of a packetConn read.
type readResult struct {
	n    int
	addr netip.AddrPort
	err  error
}

// scriptedPacketConn is a nettype.PacketConn returning a scripted sequence
// of reads, to exercise mkReceiveFunc's error handling; a real socket
// cannot be made to return EHOSTUNREACH on demand.
type scriptedPacketConn struct {
	reads []readResult // consumed in order; the last repeats if exhausted

	calls int
}

func (p *scriptedPacketConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	i := p.calls
	if i >= len(p.reads) {
		i = len(p.reads) - 1
	}
	p.calls++
	r := p.reads[i]
	return r.n, r.addr, r.err
}

func (p *scriptedPacketConn) WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error) {
	return 0, nil
}

func (p *scriptedPacketConn) Close() error                     { return nil }
func (p *scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (p *scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (p *scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (p *scriptedPacketConn) LocalAddr() net.Addr {
	// localAddrLocked type-asserts this to *net.UDPAddr.
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41641}
}

var _ nettype.PacketConn = (*scriptedPacketConn)(nil)

// recvErr returns an error shaped like a real UDP read failure, per the
// captures in #20616:
//
//	*net.OpError, read udp4 0.0.0.0:41641: recvfrom: no route to host
func recvErr(errno error) error {
	return &net.OpError{
		Op:  "read",
		Net: "udp4",
		Err: &os.SyscallError{
			Syscall: "recvfrom",
			Err:     errno,
		},
	}
}

// newReceiveFuncWithScript drives a receive func over pconn's scripted
// reads and returns it.
func newReceiveFuncWithScript(t *testing.T, pconn *scriptedPacketConn) conn.ReceiveFunc {
	t.Helper()
	c := newConn(t.Logf)
	c.pconn4.mu.Lock()
	c.pconn4.setConnLocked(pconn, "udp4", nil)
	c.pconn4.mu.Unlock()
	return c.mkReceiveFunc(&c.pconn4, "ReceiveIPv4-test", nil, nil, nil, nil, nil)
}

func callRecv(t *testing.T, recv conn.ReceiveFunc) (err error) {
	t.Helper()
	slab := make([]byte, 1280)
	packets := make([]conn.ReceivedPacket, 1)
	_, err = recv(slab, packets)
	return err
}

func TestReceiveFuncSwallowsAbortedRead(t *testing.T) {
	// A single aborted read must be retried immediately (no sleep on the
	// first abort) and must not leak to wireguard-go: the next scripted
	// result, net.ErrClosed, is what the caller sees.
	pconn := &scriptedPacketConn{reads: []readResult{
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: net.ErrClosed},
	}}
	recv := newReceiveFuncWithScript(t, pconn)

	start := time.Now()
	err := callRecv(t, recv)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
	if pconn.calls != 2 {
		t.Errorf("reads = %d, want 2", pconn.calls)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("first abort retried too slowly: %v; the first retry must not sleep", d)
	}
}

func TestReceiveFuncAbortedReadBackoff(t *testing.T) {
	// Repeated aborted reads must back off, so a kernel that fails
	// immediately instead of blocking cannot spin the loop.
	pconn := &scriptedPacketConn{reads: []readResult{
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: net.ErrClosed},
	}}
	recv := newReceiveFuncWithScript(t, pconn)

	start := time.Now()
	err := callRecv(t, recv)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
	if pconn.calls != 3 {
		t.Errorf("reads = %d, want 3", pconn.calls)
	}
	if d := time.Since(start); d < abortBackoffDuration(2) {
		t.Errorf("repeated aborts took %v, want >= one %v backoff", d, abortBackoffDuration(2))
	}
}

func TestReceiveFuncAbortedReadResetOnSuccess(t *testing.T) {
	// A successful read (even an empty one) resets the abort state, so a
	// subsequent abort is treated as a first one and does not sleep.
	pconn := &scriptedPacketConn{reads: []readResult{
		{err: recvErr(syscall.EHOSTUNREACH)},
		{n: 0, addr: netip.MustParseAddrPort("127.0.0.1:12345")},
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: net.ErrClosed},
	}}
	recv := newReceiveFuncWithScript(t, pconn)

	start := time.Now()
	err := callRecv(t, recv)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
	if pconn.calls != 4 {
		t.Errorf("reads = %d, want 4", pconn.calls)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Errorf("abort after successful read took %v; abort state should have reset", d)
	}
}

func TestReceiveFuncNonAbortErrorPropagates(t *testing.T) {
	// Errors that do not indicate a kernel read abort must still be
	// returned to wireguard-go untouched, and even with no health item
	// (health omitted, or nil) the exit must be logged.
	pconn := &scriptedPacketConn{reads: []readResult{
		{err: recvErr(syscall.EPIPE)},
	}}

	var mu sync.Mutex
	var logs []string
	c := newConn(func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	})
	c.pconn4.mu.Lock()
	c.pconn4.setConnLocked(pconn, "udp4", nil)
	c.pconn4.mu.Unlock()
	recv := c.mkReceiveFunc(&c.pconn4, "ReceiveIPv4-test", nil, nil, nil, nil, nil)

	err := callRecv(t, recv)
	if !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("err = %v, want EPIPE", err)
	}
	if pconn.calls != 1 {
		t.Errorf("reads = %d, want 1", pconn.calls)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, msg := range logs {
		if strings.Contains(msg, "Receive func ReceiveIPv4-test exiting with error") {
			return
		}
	}
	t.Errorf("exit log not found; logs = %v", logs)
}

func TestStormRebindWanted(t *testing.T) {
	tests := []struct {
		abortedReads, abortedRebinds int
		want                         bool
	}{
		{0, 0, false},
		{1, 0, false},
		{3, 0, false},
		{4, 0, true}, // first multiple of receiveAbortsRebindEvery
		{5, 0, false},
		{8, 0, true},
		{12, 0, true},
		{20, 0, true},
		{20, 5, false}, // budget exhausted
		{24, 5, false},
		{16, 4, true}, // last budget slot still available
		{24, 4, true},
	}
	for _, tt := range tests {
		if got := stormRebindWanted(tt.abortedReads, tt.abortedRebinds); got != tt.want {
			t.Errorf("stormRebindWanted(%d, %d) = %v, want %v", tt.abortedReads, tt.abortedRebinds, got, tt.want)
		}
	}
}

func TestAbortBackoffDuration(t *testing.T) {
	tests := []struct {
		abortedReads int
		want         time.Duration
	}{
		{0, 0}, // first abort retries immediately
		{1, 0},
		{2, 250 * time.Millisecond},
		{3, 500 * time.Millisecond},
		{4, time.Second},
		{5, 2 * time.Second},
		{6, 4 * time.Second},
		{7, receiveAbortBackoffMax}, // cap reached
		{8, receiveAbortBackoffMax},
		{1000, receiveAbortBackoffMax},
	}
	for _, tt := range tests {
		if got := abortBackoffDuration(tt.abortedReads); got != tt.want {
			t.Errorf("abortBackoffDuration(%d) = %v, want %v", tt.abortedReads, got, tt.want)
		}
	}
}

func TestReceiveFuncStormAttemptsRebind(t *testing.T) {
	// A sustained abort run must attempt a rebind through throttledRebind —
	// the same code the send path uses. Pin the shared throttle active so
	// the attempt is observable via the throttle log without mutating
	// sockets under the test (a bare newConn has no netMon).
	pconn := &scriptedPacketConn{reads: []readResult{
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: recvErr(syscall.EHOSTUNREACH)},
		{err: net.ErrClosed},
	}}

	var mu sync.Mutex
	throttledAttempts := 0
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(fmt.Sprintf(format, args...), "not performing \"receive-aborts\" rebind due to throttle") {
			throttledAttempts++
		}
	}

	c := newConn(logf)
	c.pconn4.mu.Lock()
	c.pconn4.setConnLocked(pconn, "udp4", nil)
	c.pconn4.mu.Unlock()
	c.lastErrRebind.Store(time.Now()) // pin the shared rebind throttle active

	recv := c.mkReceiveFunc(&c.pconn4, "ReceiveIPv4-test", nil, nil, nil, nil, nil)

	start := time.Now()
	err := callRecv(t, recv)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("err = %v, want net.ErrClosed", err)
	}
	if pconn.calls != 5 {
		t.Errorf("reads = %d, want 5", pconn.calls)
	}
	// One storm rebind attempt at 4 consecutive aborts, absorbed by the
	// active throttle.
	mu.Lock()
	got := throttledAttempts
	mu.Unlock()
	if got != 1 {
		t.Errorf("throttled rebind attempts = %d, want 1", got)
	}
	// Three backoffs before the 4th abort is observed: 250+500+1000ms.
	if d := time.Since(start); d < 1750*time.Millisecond {
		t.Errorf("storm took %v, want >= 1.75s of backoff", d)
	}
}

func TestReceiveFuncCloseWakeDuringBackoff(t *testing.T) {
	// A bind Close during a long abort backoff must wake the func
	// promptly, rather than delaying net.ErrClosed by the full backoff.
	reads := make([]readResult, 0, 30)
	for range 30 {
		reads = append(reads, readResult{err: recvErr(syscall.EHOSTUNREACH)})
	}
	reads = append(reads, readResult{err: net.ErrClosed})
	pconn := &scriptedPacketConn{reads: reads}

	c := newConn(t.Logf)
	c.pconn4.mu.Lock()
	c.pconn4.setConnLocked(pconn, "udp4", nil)
	c.pconn4.mu.Unlock()
	// Pin the shared rebind throttle active: this test is about the close
	// wake, not the storm remedy, and a bare newConn has no netMon for an
	// actual rebind to use.
	c.lastErrRebind.Store(time.Now())

	// Install a close-wake channel manually (a bare newConn never ran
	// connBind.Open); without it the scripted aborts would take minutes
	// of cumulative backoff.
	wake := make(chan struct{})
	c.bind.mu.Lock()
	c.bind.closedCh = wake
	c.bind.mu.Unlock()

	recv := c.mkReceiveFunc(&c.pconn4, "ReceiveIPv4-test", nil, nil, nil, nil, nil)

	done := make(chan error, 1)
	go func() { done <- callRecv(t, recv) }()

	// Wait until we are inside a backoff sleep, then close the bind.
	time.Sleep(600 * time.Millisecond)
	close(wake)

	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("err = %v, want net.ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("close during backoff did not wake the receive func")
	}
}

func TestConnBindCloseWakeLifecycle(t *testing.T) {
	// Open touches c.health and c.metrics (receiveIPv4 takes pointers into
	// them) and LocalPort (needs a conn under pconn4); production wires
	// these in NewConn.
	bus := eventbus.New()
	c := newConn(t.Logf)
	c.health = health.NewTracker(bus)
	c.metrics = new(metrics) // receiveIPv4 takes pointers into it
	// Open reads LocalPort, which needs a conn installed under pconn4.
	c.pconn4.mu.Lock()
	c.pconn4.setConnLocked(&scriptedPacketConn{}, "udp4", nil)
	c.pconn4.mu.Unlock()
	if _, _, err := c.bind.Open(0); err != nil {
		t.Fatal(err)
	}
	wake := c.bind.closeWake()
	if wake == nil {
		t.Fatal("closeWake nil after Open")
	}
	select {
	case <-wake:
		t.Fatal("closeWake closed before Close")
	default:
	}
	if err := c.bind.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
	default:
		t.Fatal("closeWake not closed after Close")
	}
	// Reopening mints a fresh channel; the old one stays closed.
	if _, _, err := c.bind.Open(0); err != nil {
		t.Fatal(err)
	}
	wake2 := c.bind.closeWake()
	if wake2 == nil {
		t.Fatal("closeWake nil after reopen")
	}
	select {
	case <-wake2:
		t.Fatal("fresh closeWake already closed")
	default:
	}
}
