// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/health"
	"tailscale.com/types/nettype"
	"tailscale.com/util/eventbus/eventbustest"
)

// scriptedPacketConn returns scripted errors; nil yields an empty datagram.
type scriptedPacketConn struct {
	errors []error
	calls  int
}

func (p *scriptedPacketConn) ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error) {
	err := p.errors[p.calls]
	p.calls++
	return 0, netip.AddrPort{}, err
}

func (*scriptedPacketConn) WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error) {
	return 0, nil
}
func (*scriptedPacketConn) Close() error                     { return nil }
func (*scriptedPacketConn) SetDeadline(time.Time) error      { return nil }
func (*scriptedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*scriptedPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (*scriptedPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }

var _ nettype.PacketConn = (*scriptedPacketConn)(nil)

func TestReceiveFuncRetriesErrors(t *testing.T) {
	for _, err := range []error{
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.Errno(10065),
		syscall.Errno(10051),
		syscall.EADDRNOTAVAIL,
		syscall.Errno(10049),
		syscall.EBADF,
		syscall.ENOTSOCK,
		syscall.ECONNRESET,
		syscall.ECONNREFUSED,
		errors.New("unexpected error"),
	} {
		t.Run(err.Error(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := readErr(err)
				// Errors around an empty read; each error is retried after a delay.
				pconn := &scriptedPacketConn{errors: []error{e, e, nil, e, errReadClosed}}
				const wantErrs = 3
				c, recvFn := newScriptedRecv(t, pconn)
				before := metricRecvUDPError.Value()
				start := time.Now()
				if err := recv(recvFn); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("recv = %v, want net.ErrClosed", err)
				}
				if pconn.calls != len(pconn.errors) {
					t.Fatalf("reads = %d, want %d", pconn.calls, len(pconn.errors))
				}
				if got := metricRecvUDPError.Value() - before; got != wantErrs {
					t.Errorf("error metric grew by %d, want %d", got, wantErrs)
				}
				if got, want := time.Since(start), wantErrs*readErrRetryDelay; got != want {
					t.Errorf("waited %v, want %v", got, want)
				}
				c.connCtxCancel()
				if err := recv(recvFn); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("error after cancellation = %v, want net.ErrClosed", err)
				}
			})
		})
	}
}

var errReadClosed = fmt.Errorf("read: %w", net.ErrClosed)

func readErr(errno error) error {
	return &net.OpError{Op: "read", Net: "udp4", Err: &os.SyscallError{Syscall: "recvfrom", Err: errno}}
}

func recv(fn conn.ReceiveFunc) error {
	_, err := fn(make([]byte, 1280), make([]conn.ReceivedPacket, 1))
	return err
}

// newScriptedRecv returns a minimal Conn and an IPv4 receive func reading
// from pconn.
func newScriptedRecv(t *testing.T, pconn *scriptedPacketConn) (*Conn, conn.ReceiveFunc) {
	c := newConn(t.Logf)
	c.connCtx, c.connCtxCancel = context.WithCancel(t.Context())
	t.Cleanup(c.connCtxCancel)
	c.health = health.NewTracker(eventbustest.NewBus(t))
	c.pconn4.setConnLocked([]nettype.PacketConn{pconn}, 1, "udp4", nil)
	return c, c.mkReceiveFunc(udpReceiveConfig{ruc: &c.pconn4, family: "ReceiveIPv4-test"})
}

func TestReceiveFuncCloseInterruptsRetryDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, recvFn := newScriptedRecv(t, &scriptedPacketConn{errors: slices.Repeat([]error{readErr(syscall.ECONNRESET)}, 100)})
		done := make(chan error, 1)
		go func() { done <- recv(recvFn) }()

		time.Sleep(10*readErrRetryDelay + readErrRetryDelay/2) // mid-way through a retry delay
		c.connCtxCancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("recv = %v, want net.ErrClosed", err)
			}
		default:
			t.Fatal("recv still blocked after close")
		}
	})
}

func TestReceiveFuncBrokenHealth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := readErr(syscall.ECONNRESET)
		var script []error
		script = append(script, e, e, e, errReadClosed) // call 1: a few errors
		// call 2: over readErrBrokenAfter of retries
		script = append(script, slices.Repeat([]error{e}, int(readErrBrokenAfter/readErrRetryDelay)+1)...)
		script = append(script, errReadClosed, nil, errReadClosed) // call 3: a successful read
		c, recvFn := newScriptedRecv(t, &scriptedPacketConn{errors: script})
		stats := c.health.ReceiveFuncStats("ReceiveIPv4-test")

		for i, want := range []bool{false, true, false} {
			recv(recvFn)
			if got := stats.Broken(); got != want {
				t.Errorf("after call %d: Broken = %v, want %v", i+1, got, want)
			}
		}

		stats.SetBroken(true)
		c.mkReceiveFunc(udpReceiveConfig{ruc: &c.pconn4, family: "ReceiveIPv4-test"})
		if stats.Broken() {
			t.Error("still broken after a new receive func")
		}
	})
}
