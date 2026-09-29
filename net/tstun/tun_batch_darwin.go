// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin && !ios

package tstun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"tailscale.com/envknob"
	"tailscale.com/net/msgx"
	"tailscale.com/types/logger"
)

// This file implements batched reads and writes on macOS utun devices.
//
// A utun is a kernel control socket, and the kernel's recvmsg_x and
// sendmsg_x system calls work on it just as on a UDP socket. Two things stand
// in the way by default. The driver only queues one packet in the socket at
// a time (utun_max_pending_packets defaults to 1 in xnu's if_utun.c), so
// there is never more than one packet to read; the UTUN_OPT_MAX_PENDING_PACKETS
// socket option raises that. And wireguard-go's tun.Device for Darwin reads
// and writes one packet per call. [utunBatchDevice] wraps it to do both in
// batches when [msgx.Available], falling back to the wrapped device
// otherwise.

const (
	// sysprotoControl is SYSPROTO_CONTROL, the level for utun socket options.
	sysprotoControl = 2
	// utunOptMaxPendingPackets is UTUN_OPT_MAX_PENDING_PACKETS (net/if_utun.h):
	// how many packets the kernel may queue on the control socket before
	// it stops the interface's output until userspace reads.
	utunOptMaxPendingPackets = 16
	// utunHeaderLen is the length of the address family header the utun
	// control socket prepends to each packet.
	utunHeaderLen = 4

	// utunPendingPackets is the queue depth we ask for. wireguard-go's
	// batching slab holds at most this many packets per read anyway.
	utunPendingPackets = 128
	// utunReadSlack is extra room per read slot beyond the MTU, in case a
	// packet slightly exceeds it. Oversized packets are truncated.
	utunReadSlack = 64
	// utunMTURefresh is how often Read re-queries the device MTU, which
	// sizes its read slots. Querying is an ioctl, so not per read.
	utunMTURefresh = time.Second
)

// debugTUNBatch (TS_DEBUG_TUN_BATCH) disables utun batching when "0".
//
// TODO(bradfitz): remove once the evaluation is done.
var debugTUNBatch = envknob.RegisterOptBool("TS_DEBUG_TUN_BATCH")

func init() {
	wrapTUNBatching = maybeWrapUTunBatching
}

// maybeWrapUTunBatching returns dev wrapped in a [utunBatchDevice] if batched
// I/O is available, else dev.
func maybeWrapUTunBatching(dev tun.Device, logf logger.Logf) tun.Device {
	if v, ok := debugTUNBatch().Get(); ok && !v {
		return dev
	}
	if !msgx.Available() {
		logf("tstun: utun batching unavailable: %v", msgx.UnavailableReason())
		return dev
	}
	f := dev.File()
	if f == nil {
		return dev
	}
	rc, err := f.SyscallConn()
	if err != nil {
		logf("tstun: utun batching unavailable: %v", err)
		return dev
	}
	var soErr error
	if err := rc.Control(func(fd uintptr) {
		soErr = unix.SetsockoptInt(int(fd), sysprotoControl, utunOptMaxPendingPackets, utunPendingPackets)
	}); err != nil {
		soErr = err
	}
	if soErr != nil {
		logf("tstun: utun batching unavailable: setting UTUN_OPT_MAX_PENDING_PACKETS: %v", soErr)
		return dev
	}
	logf("tstun: using batched utun reads and writes")
	return &utunBatchDevice{Device: dev, rc: rc, logf: logf}
}

// utunBatchDevice is a [tun.Device] that reads and writes batches of packets
// on a utun using recvmsg_x and sendmsg_x. See the file comment.
type utunBatchDevice struct {
	tun.Device // the wrapped utun device
	rc         syscall.RawConn
	logf       logger.Logf

	// disabled is set after an unexpected error from the batched path;
	// from then on everything goes to the wrapped device.
	disabled atomic.Bool

	// readMu guards the fields below. wireguard-go has one reader, but the
	// guard keeps that from being a caller obligation.
	readMu     sync.Mutex
	msgs       [msgx.MaxBatch]msgx.Message
	mtu        int
	mtuChecked time.Time
}

// BatchSize implements [tun.Device].
func (d *utunBatchDevice) BatchSize() int {
	return msgx.MaxBatch
}

// disable stops batched I/O for good after err.
func (d *utunBatchDevice) disable(op string, err error) {
	if d.disabled.CompareAndSwap(false, true) {
		d.logf("tstun: disabling batched utun %s after error: %v", op, err)
	}
}

// slotMTULocked returns the MTU to size read slots with, refreshing it from
// the device at most once per utunMTURefresh.
func (d *utunBatchDevice) slotMTULocked() int {
	if now := time.Now(); d.mtu == 0 || now.Sub(d.mtuChecked) > utunMTURefresh {
		if mtu, err := d.Device.MTU(); err == nil && mtu > 0 {
			d.mtu = mtu
		} else if d.mtu == 0 {
			d.mtu = int(DefaultTUNMTU())
		}
		d.mtuChecked = now
	}
	return d.mtu
}

// Read implements [tun.Device].
func (d *utunBatchDevice) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if d.disabled.Load() {
		return d.Device.Read(slab, packets)
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()

	const spacing = tun.ReadPacketSpacing
	mtu := d.slotMTULocked()
	payloadLen := utunHeaderLen + mtu + utunReadSlack
	stride := spacing + payloadLen
	n := min(len(packets), (len(slab)-spacing)/stride, len(d.msgs))
	if n <= 1 {
		return d.Device.Read(slab, packets)
	}
	msgs := d.msgs[:n]
	for i := range msgs {
		start := i*stride + spacing
		msgs[i] = msgx.Message{Payload: slab[start : start+payloadLen]}
	}
	got, err := msgx.Recv(d.rc, msgs)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return 0, err
		}
		d.disable("read", err)
		return d.Device.Read(slab, packets)
	}
	out := 0
	for i, m := range msgs[:got] {
		if m.N < utunHeaderLen {
			continue
		}
		packets[out] = tun.ReadPacket{
			Offset: i*stride + spacing + utunHeaderLen,
			Size:   m.N - utunHeaderLen,
		}
		out++
	}
	return out, nil
}

// Write implements [tun.Device]. It prepends the utun address family header
// to each packet in the space before offset, as the wrapped device does, and
// writes them with as few system calls as possible.
func (d *utunBatchDevice) Write(bufs [][]byte, offset int) (int, error) {
	if d.disabled.Load() || len(bufs) <= 1 {
		return d.Device.Write(bufs, offset)
	}
	if offset < utunHeaderLen {
		return 0, io.ErrShortBuffer
	}
	payloads := make([][]byte, 0, len(bufs))
	for i, buf := range bufs {
		hdr := buf[offset-utunHeaderLen : offset]
		hdr[0], hdr[1], hdr[2] = 0, 0, 0
		switch buf[offset] >> 4 {
		case 4:
			hdr[3] = unix.AF_INET
		case 6:
			hdr[3] = unix.AF_INET6
		default:
			return i, unix.EAFNOSUPPORT
		}
		payloads = append(payloads, buf[offset-utunHeaderLen:])
	}
	written := 0
	for rem := payloads; len(rem) > 0; {
		n, err := msgx.Send(d.rc, rem)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return written, err
			}
			d.disable("write", err)
			// The wrapped device rewrites the header itself.
			m, err := d.Device.Write(bufs[written:], offset)
			return written + m, err
		}
		if n == 0 {
			return written, fmt.Errorf("tstun: sendmsg_x accepted no packets")
		}
		rem = rem[n:]
		written += n
	}
	return written, nil
}
