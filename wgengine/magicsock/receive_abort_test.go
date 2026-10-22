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
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"tailscale.com/types/nettype"
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

func TestReceiveFuncReadFeedback(t *testing.T) {
	for _, tt := range []struct {
		err      error
		feedback bool
	}{
		{syscall.EHOSTUNREACH, runtime.GOOS != "windows"},
		{syscall.ENETUNREACH, runtime.GOOS != "windows"},
		{syscall.Errno(10065), runtime.GOOS == "windows"},
		{syscall.Errno(10051), runtime.GOOS == "windows"},
		{syscall.EBADF, false},
		{syscall.ENOTSOCK, false},
		{syscall.ECONNRESET, false},
		{syscall.ECONNREFUSED, false},
		{errors.New("unexpected error"), false},
	} {
		t.Run(tt.err.Error(), func(t *testing.T) {
			wrapped := &net.OpError{Op: "read", Net: "udp4", Err: &os.SyscallError{
				Syscall: "recvfrom", Err: tt.err,
			}}
			pconn := &scriptedPacketConn{}
			for range 12 {
				pconn.errors = append(pconn.errors, wrapped)
			}
			pconn.errors = append(pconn.errors, nil, wrapped, fmt.Errorf("read: %w", net.ErrClosed))
			c := newConn(t.Logf)
			c.connCtx, c.connCtxCancel = context.WithCancel(t.Context())
			t.Cleanup(c.connCtxCancel)
			c.pconn4.setConnLocked([]nettype.PacketConn{pconn}, 1, "udp4", nil)
			recv := c.mkReceiveFunc(udpReceiveConfig{ruc: &c.pconn4, family: "ReceiveIPv4-test"})
			slab := make([]byte, 1280)
			packets := make([]conn.ReceivedPacket, 1)
			n, err := recv(slab, packets)
			if !tt.feedback {
				if n != 0 || err != wrapped || pconn.calls != 1 {
					t.Fatalf("non-feedback error: got (%d, %v), reads=%d", n, err, pconn.calls)
				}
				return
			}
			if n != 0 || !errors.Is(err, net.ErrClosed) {
				t.Fatalf("got (%d, %v), want (0, net.ErrClosed)", n, err)
			}
			if pconn.calls != len(pconn.errors) {
				t.Fatalf("reads = %d, want %d", pconn.calls, len(pconn.errors))
			}
			c.connCtxCancel()
			if _, err := recv(slab, packets); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("error after cancellation = %v, want net.ErrClosed", err)
			}
		})
	}
}
