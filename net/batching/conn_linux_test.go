// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package batching

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	qt "github.com/frankban/quicktest"
	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"tailscale.com/net/neterror"
	"tailscale.com/net/packet"
)

func Test_linuxBatchingConn_splitCoalescedMessages(t *testing.T) {
	c := &linuxBatchingConn{}

	newMsg := func(n int, gso uint16) ipv6.Message {
		msg := ipv6.Message{
			Buffers: [][]byte{make([]byte, 1024)},
			N:       n,
			OOB:     gsoControl(gso),
		}
		if gso > 0 {
			msg.NN = len(msg.OOB)
		}
		return msg
	}

	cases := []struct {
		name        string
		msgs        []ipv6.Message
		firstMsgAt  int
		wantNumEval int
		wantMsgLens []int
		wantErr     bool
	}{
		{
			name: "second-last-split-last-empty",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(3, 1),
				newMsg(0, 0),
			},
			firstMsgAt:  2,
			wantNumEval: 3,
			wantMsgLens: []int{1, 1, 1, 0},
			wantErr:     false,
		},
		{
			name: "second-last-no-split-last-empty",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(0, 0),
			},
			firstMsgAt:  2,
			wantNumEval: 1,
			wantMsgLens: []int{1, 0, 0, 0},
			wantErr:     false,
		},
		{
			name: "second-last-no-split-last-no-split",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(1, 0),
			},
			firstMsgAt:  2,
			wantNumEval: 2,
			wantMsgLens: []int{1, 1, 0, 0},
			wantErr:     false,
		},
		{
			name: "second-last-no-split-last-split",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(3, 1),
			},
			firstMsgAt:  2,
			wantNumEval: 4,
			wantMsgLens: []int{1, 1, 1, 1},
			wantErr:     false,
		},
		{
			name: "second-last-split-last-split",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(2, 1),
				newMsg(2, 1),
			},
			firstMsgAt:  2,
			wantNumEval: 4,
			wantMsgLens: []int{1, 1, 1, 1},
			wantErr:     false,
		},
		{
			name: "second-last-no-split-last-split-overflow",
			msgs: []ipv6.Message{
				newMsg(0, 0),
				newMsg(0, 0),
				newMsg(1, 0),
				newMsg(4, 1),
			},
			firstMsgAt:  2,
			wantNumEval: 4,
			wantMsgLens: []int{1, 1, 1, 1},
			wantErr:     true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.splitCoalescedMessages(tt.msgs, 2)
			if err != nil && !tt.wantErr {
				t.Fatalf("err: %v", err)
			}
			if got != tt.wantNumEval {
				t.Fatalf("got to eval: %d want: %d", got, tt.wantNumEval)
			}
			for i, msg := range tt.msgs {
				if msg.N != tt.wantMsgLens[i] {
					t.Fatalf("msg[%d].N: %d want: %d", i, msg.N, tt.wantMsgLens[i])
				}
			}
		})
	}
}

func Test_linuxBatchingConn_coalesceMessages(t *testing.T) {
	withGeneveSpace := func(len, cap int) []byte {
		return make([]byte, len+packet.GeneveFixedHeaderLength, cap+packet.GeneveFixedHeaderLength)
	}

	geneve := packet.GeneveHeader{
		Protocol: packet.GeneveProtocolWireGuard,
	}
	geneve.VNI.Set(1)

	cases := []struct {
		name              string
		buffs             [][]byte
		geneve            packet.GeneveHeader
		neverGSOEqualTail bool
		// Each wantLens slice corresponds to the Buffers of a single coalesced message,
		// and each int is the expected length of the corresponding Buffer[i].
		wantLens [][]int
		wantGSO  []int
		// wantSentinelAtTail[i], when true, asserts that the tail entry of
		// msgs[i].Buffers is the shared neverGSOEqualTailSentinelPayload slice.
		wantSentinelAtTail []bool
	}{
		{
			name: "one-message-no-coalesce",
			buffs: [][]byte{
				withGeneveSpace(1, 1),
			},
			wantLens: [][]int{{1}},
			wantGSO:  []int{0},
		},
		{
			name: "one-message-no-coalesce-vni-isSet",
			buffs: [][]byte{
				withGeneveSpace(1, 1),
			},
			geneve:   geneve,
			wantLens: [][]int{{1 + packet.GeneveFixedHeaderLength}},
			wantGSO:  []int{0},
		},
		{
			name: "two-messages-equal-len-coalesce",
			buffs: [][]byte{
				withGeneveSpace(1, 2),
				withGeneveSpace(1, 1),
			},
			wantLens: [][]int{{1, 1}},
			wantGSO:  []int{1},
		},
		{
			name: "two-messages-equal-len-coalesce-vni-isSet",
			buffs: [][]byte{
				withGeneveSpace(1, 2+packet.GeneveFixedHeaderLength),
				withGeneveSpace(1, 1),
			},
			geneve:   geneve,
			wantLens: [][]int{{1 + packet.GeneveFixedHeaderLength, 1 + packet.GeneveFixedHeaderLength}},
			wantGSO:  []int{1 + packet.GeneveFixedHeaderLength},
		},
		{
			name: "two-messages-unequal-len-coalesce",
			buffs: [][]byte{
				withGeneveSpace(2, 3),
				withGeneveSpace(1, 1),
			},
			wantLens: [][]int{{2, 1}},
			wantGSO:  []int{2},
		},
		{
			name: "two-messages-unequal-len-coalesce-vni-isSet",
			buffs: [][]byte{
				withGeneveSpace(2, 3+packet.GeneveFixedHeaderLength),
				withGeneveSpace(1, 1),
			},
			geneve:   geneve,
			wantLens: [][]int{{2 + packet.GeneveFixedHeaderLength, 1 + packet.GeneveFixedHeaderLength}},
			wantGSO:  []int{2 + packet.GeneveFixedHeaderLength},
		},
		{
			name: "three-messages-second-unequal-len-coalesce",
			buffs: [][]byte{
				withGeneveSpace(2, 3),
				withGeneveSpace(1, 1),
				withGeneveSpace(2, 2),
			},
			wantLens: [][]int{{2, 1}, {2}},
			wantGSO:  []int{2, 0},
		},
		{
			name: "three-messages-second-unequal-len-coalesce-vni-isSet",
			buffs: [][]byte{
				withGeneveSpace(2, 3+(2*packet.GeneveFixedHeaderLength)),
				withGeneveSpace(1, 1),
				withGeneveSpace(2, 2),
			},
			geneve:   geneve,
			wantLens: [][]int{{2 + packet.GeneveFixedHeaderLength, 1 + packet.GeneveFixedHeaderLength}, {2 + packet.GeneveFixedHeaderLength}},
			wantGSO:  []int{2 + packet.GeneveFixedHeaderLength, 0},
		},
		{
			name: "three-messages-limited-cap-coalesce",
			buffs: [][]byte{
				withGeneveSpace(2, 4),
				withGeneveSpace(2, 2),
				withGeneveSpace(2, 2),
			},
			wantLens: [][]int{{2, 2, 2}},
			wantGSO:  []int{2},
		},
		{
			name: "three-messages-limited-cap-coalesce-vni-isSet",
			buffs: [][]byte{
				withGeneveSpace(2, 4+packet.GeneveFixedHeaderLength),
				withGeneveSpace(2, 2),
				withGeneveSpace(2, 2),
			},
			geneve:   geneve,
			wantLens: [][]int{{2 + packet.GeneveFixedHeaderLength, 2 + packet.GeneveFixedHeaderLength, 2 + packet.GeneveFixedHeaderLength}},
			wantGSO:  []int{2 + packet.GeneveFixedHeaderLength},
		},
		{
			name: "two-equal-len-coalesce-neverGSOEqualTail-appends-sentinel",
			buffs: [][]byte{
				withGeneveSpace(3, 3),
				withGeneveSpace(3, 3),
			},
			neverGSOEqualTail:  true,
			wantLens:           [][]int{{3, 3, len(neverGSOEqualTailSentinelPayload)}},
			wantGSO:            []int{3},
			wantSentinelAtTail: []bool{true},
		},
		{
			name: "two-equal-len-coalesce-neverGSOEqualTail-vni-isSet-appends-sentinel",
			buffs: [][]byte{
				withGeneveSpace(3, 3+packet.GeneveFixedHeaderLength),
				withGeneveSpace(3, 3),
			},
			geneve:             geneve,
			neverGSOEqualTail:  true,
			wantLens:           [][]int{{3 + packet.GeneveFixedHeaderLength, 3 + packet.GeneveFixedHeaderLength, len(neverGSOEqualTailSentinelPayload)}},
			wantGSO:            []int{3 + packet.GeneveFixedHeaderLength},
			wantSentinelAtTail: []bool{true},
		},
		{
			name: "two-unequal-len-coalesce-neverGSOEqualTail-smaller-tail-no-sentinel",
			buffs: [][]byte{
				withGeneveSpace(3, 3),
				withGeneveSpace(2, 2),
			},
			neverGSOEqualTail: true,
			wantLens:          [][]int{{3, 2}},
			wantGSO:           []int{3},
		},
		{
			name: "one-byte-tail-neverGSOEqualTail-not-coalesced",
			// okToCoalesceWithSentinel is false when msgLen == 1 and
			// neverGSOEqualTail is set; the 1-byte tail is split into
			// its own non-coalesced singleton msg.
			buffs: [][]byte{
				withGeneveSpace(2, 2),
				withGeneveSpace(1, 1),
			},
			neverGSOEqualTail: true,
			wantLens:          [][]int{{2}, {1}},
			wantGSO:           []int{0, 0},
		},
		{
			name: "one-byte-tail-neverGSOEqualTail-vni-isSet-coalesced",
			// With vniIsSet, msgLen always includes the Geneve header, so
			// okToCoalesceWithSentinel is true even for "1-byte payloads".
			// The naturally smaller tail short-circuits the sentinel.
			buffs: [][]byte{
				withGeneveSpace(2, 2+packet.GeneveFixedHeaderLength),
				withGeneveSpace(1, 1),
			},
			geneve:            geneve,
			neverGSOEqualTail: true,
			wantLens:          [][]int{{2 + packet.GeneveFixedHeaderLength, 1 + packet.GeneveFixedHeaderLength}},
			wantGSO:           []int{2 + packet.GeneveFixedHeaderLength},
		},
		{
			name: "batch-boundary-sentinel-appended-on-prior-batch-neverGSOEqualTail",
			// The 4th buff (length 5) is larger than gsoSize=3 so it
			// closes the first batch. The first batch has dgramCnt > 1 and
			// no smaller tail, so the sentinel is appended before starting
			// the new batch.
			buffs: [][]byte{
				withGeneveSpace(3, 3),
				withGeneveSpace(3, 3),
				withGeneveSpace(3, 3),
				withGeneveSpace(5, 5),
			},
			neverGSOEqualTail:  true,
			wantLens:           [][]int{{3, 3, 3, len(neverGSOEqualTailSentinelPayload)}, {5}},
			wantGSO:            []int{3, 0},
			wantSentinelAtTail: []bool{true, false},
		},
		{
			name: "single-buff-neverGSOEqualTail-no-sentinel",
			// Only one datagram, no GSO happening, no sentinel.
			buffs: [][]byte{
				withGeneveSpace(3, 3),
			},
			neverGSOEqualTail: true,
			wantLens:          [][]int{{3}},
			wantGSO:           []int{0},
		},
		{
			name: "equal-len-then-smaller-tail-then-equal-neverGSOEqualTail",
			// The smaller tail ends the first batch with no sentinel
			// (variation already provided), then a second singleton batch
			// is started for the trailing equal-length buff.
			buffs: [][]byte{
				withGeneveSpace(3, 3),
				withGeneveSpace(3, 3),
				withGeneveSpace(2, 2),
				withGeneveSpace(3, 3),
			},
			neverGSOEqualTail: true,
			wantLens:          [][]int{{3, 3, 2}, {3}},
			wantGSO:           []int{3, 0},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := &linuxBatchingConn{}
			addr := &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 1,
			}
			msgs := make([]ipv6.Message, len(tt.buffs))
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].OOB = make([]byte, controlMessageSize)
			}
			got := c.coalesceMessages(addr, tt.geneve, tt.buffs, msgs, packet.GeneveFixedHeaderLength, tt.neverGSOEqualTail)
			if got != len(tt.wantLens) {
				t.Fatalf("got len %d want: %d", got, len(tt.wantLens))
			}
			for i := range got {
				if msgs[i].Addr != addr {
					t.Errorf("msgs[%d].Addr != passed addr", i)
				}
				if len(msgs[i].Buffers) != len(tt.wantLens[i]) {
					t.Fatalf("len(msgs[%d].Buffers) %d != %d", i, len(msgs[i].Buffers), len(tt.wantLens[i]))
				}
				for j := range tt.wantLens[i] {
					gotLen := len(msgs[i].Buffers[j])
					if gotLen != tt.wantLens[i][j] {
						t.Errorf("len(msgs[%d].Buffers[%d]) %d != %d", i, j, gotLen, tt.wantLens[i][j])
					}
				}

				wantSentinel := i < len(tt.wantSentinelAtTail) && tt.wantSentinelAtTail[i]
				if wantSentinel {
					tail := msgs[i].Buffers[len(msgs[i].Buffers)-1]
					if len(tail) != len(neverGSOEqualTailSentinelPayload) ||
						&tail[0] != &neverGSOEqualTailSentinelPayload[0] {
						t.Errorf("msgs[%d] tail buffer is not neverGSOEqualTailSentinelPayload", i)
					}
				}

				// coalesceMessages calls setGSOSizeInControl, which uses a cmsg
				// type of UDP_SEGMENT, and getGSOSizeInControl scans for a cmsg
				// type of UDP_GRO. Therefore, we have to use the lower-level
				// getDataFromControl in order to specify the cmsg type of
				// interest for this test.
				data, err := getDataFromControl(msgs[i].OOB, unix.SOL_UDP, unix.UDP_SEGMENT, 2)
				if err != nil {
					t.Fatalf("msgs[%d] getDataFromControl err: %v", i, err)
				}
				var gotGSO int
				if len(data) >= 2 {
					gotGSO = int(binary.NativeEndian.Uint16(data))
				}
				if gotGSO != tt.wantGSO[i] {
					t.Errorf("msgs[%d] gsoSize %d != %d", i, gotGSO, tt.wantGSO[i])
				}
			}
		})
	}
}

// fakeBatchWriter is an xnetBatchReaderWriter that records the Buffers length
// of each message handed to WriteBatch, and optionally fails the first call
// with an error that triggers neterror.ShouldDisableUDPGSO.
type fakeBatchWriter struct {
	gotBuffersLen [][]int // Buffers len of each msg, per WriteBatch call
	failFirst     bool
}

func (f *fakeBatchWriter) ReadBatch([]ipv6.Message, int) (int, error) { return 0, nil }

func (f *fakeBatchWriter) WriteBatch(msgs []ipv6.Message, _ int) (int, error) {
	snap := make([]int, len(msgs))
	for i := range msgs {
		snap[i] = len(msgs[i].Buffers)
	}
	f.gotBuffersLen = append(f.gotBuffersLen, snap)
	if f.failFirst && len(f.gotBuffersLen) == 1 {
		return 0, &os.SyscallError{Syscall: "sendmmsg", Err: unix.EIO}
	}
	return len(msgs), nil
}

// Test_linuxBatchingConn_WriteBatchTo_resetsBuffersOnGSORetry verifies that
// when a coalesced (scatter-gather) write fails and triggers the GSO-disable
// goto retry, the non-coalesce retry pass resets each message's Buffers back to
// length 1 rather than leaving stale iovecs appended by coalesceMessages.
func Test_linuxBatchingConn_WriteBatchTo_resetsBuffersOnGSORetry(t *testing.T) {
	uc, err := net.ListenUDP("udp4", nil) // only for pc.LocalAddr() in the error path
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	xpc := &fakeBatchWriter{failFirst: true}
	c := &linuxBatchingConn{
		pc:  uc,
		xpc: xpc,
		sendBatchPool: sync.Pool{New: func() any {
			ua := &net.UDPAddr{IP: make([]byte, 16)}
			msgs := make([]ipv6.Message, 8)
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].Addr = ua
				msgs[i].OOB = make([]byte, controlMessageSize)
			}
			return &sendBatch{ua: ua, msgs: msgs}
		}},
	}
	c.txOffload.Store(true) // force the coalesce path on the first pass

	// Two equal-length buffs coalesce into a single msg whose Buffers grows
	// to len 2 (scatter-gather) on the first pass.
	buffs := [][]byte{make([]byte, 32), make([]byte, 32)}

	err = c.WriteBatchTo(buffs, netip.MustParseAddrPort("127.0.0.1:1"), packet.GeneveHeader{}, 0)

	// The retry path always returns ErrUDPGSODisabled wrapping the retry's
	// result (nil here).
	if _, ok := errors.AsType[neterror.ErrUDPGSODisabled](err); !ok {
		t.Fatalf("got %v, want ErrUDPGSODisabled", err)
	}
	if len(xpc.gotBuffersLen) != 2 {
		t.Fatalf("got %d WriteBatch calls, want 2", len(xpc.gotBuffersLen))
	}
	// First (coalesced) call: one msg with 2 iovecs — confirms the precondition
	// that coalesceMessages grew Buffers past length 1.
	if got := xpc.gotBuffersLen[0]; len(got) != 1 || got[0] != 2 {
		t.Fatalf("first call buffers = %v, want [2]", got)
	}
	// Retry (non-coalesce) call: sends one msg per buff...
	if got := len(xpc.gotBuffersLen[1]); got != len(buffs) {
		t.Fatalf("retry call sent %d msgs, want %d", got, len(buffs))
	}
	// ...and the fix must have reset every msg's Buffers back to len 1.
	for i, n := range xpc.gotBuffersLen[1] {
		if n != 1 {
			t.Errorf("retry msg[%d] Buffers len = %d, want 1", i, n)
		}
	}
}

// Test_linuxBatchingConn_WriteBatchTo_offsetStableOnNonCoalesceRetry verifies
// that the Geneve header offset adjustment in the non-coalesce path is derived
// fresh from the original offset on each pass, rather than accumulating across a
// goto retry. The non-coalesce branch runs on both passes when neverGSOEqualTail
// is set and the batch is small enough to skip coalescing: the first pass fails
// with an error that disables GSO, and the retry re-enters the same branch.
// Since callers pass offset == GeneveFixedHeaderLength, a stale (accumulating)
// offset would underflow to -GeneveFixedHeaderLength and panic on buffs[i][-8:].
func Test_linuxBatchingConn_WriteBatchTo_offsetStableOnNonCoalesceRetry(t *testing.T) {
	uc, err := net.ListenUDP("udp4", nil) // only for pc.LocalAddr() in the error path
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()

	xpc := &fakeBatchWriter{failFirst: true}
	c := &linuxBatchingConn{
		pc:  uc,
		xpc: xpc,
		sendBatchPool: sync.Pool{New: func() any {
			ua := &net.UDPAddr{IP: make([]byte, 16)}
			msgs := make([]ipv6.Message, appendSentinelTailBatchSizeThreshold)
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].Addr = ua
				msgs[i].OOB = make([]byte, controlMessageSize)
			}
			return &sendBatch{ua: ua, msgs: msgs}
		}},
	}
	c.txOffload.Store(true)
	// neverGSOEqualTail set + a sub-threshold batch forces the non-coalesce
	// path while txOffload is still enabled, so the GSO-disable retry re-enters
	// the non-coalesce branch a second time.
	var neverGSOEqualTail atomic.Bool
	neverGSOEqualTail.Store(true)
	c.neverGSOEqualTail = &neverGSOEqualTail

	// VNI set so the non-coalesce branch performs the offset -= GeneveFixedHeaderLength
	// adjustment; offset == GeneveFixedHeaderLength as the production caller requires.
	geneve := packet.GeneveHeader{Protocol: packet.GeneveProtocolWireGuard}
	geneve.VNI.Set(1)
	offset := packet.GeneveFixedHeaderLength

	// Stay below appendSentinelTailBatchSizeThreshold so coalescing is skipped
	// and we take the non-coalesce branch on both passes.
	const nBuffs = appendSentinelTailBatchSizeThreshold - 1
	buffs := make([][]byte, nBuffs)
	for i := range buffs {
		buffs[i] = make([]byte, 32)
	}

	// Must not panic: each pass recomputes the offset from the original.
	err = c.WriteBatchTo(buffs, netip.MustParseAddrPort("127.0.0.1:1"), geneve, offset)

	if _, ok := errors.AsType[neterror.ErrUDPGSODisabled](err); !ok {
		t.Fatalf("got %v, want ErrUDPGSODisabled", err)
	}
	if len(xpc.gotBuffersLen) != 2 {
		t.Fatalf("got %d WriteBatch calls, want 2 (initial + retry)", len(xpc.gotBuffersLen))
	}
	// Both passes take the non-coalesce branch: one msg per buff, no coalescing.
	for call, got := range xpc.gotBuffersLen {
		if len(got) != len(buffs) {
			t.Errorf("call %d sent %d msgs, want %d", call, len(got), len(buffs))
		}
	}
}

func TestMinReadBatchMsgsLen(t *testing.T) {
	// So long as magicsock uses [Conn], and [wireguard-go/conn.Bind] API is
	// shaped for wireguard-go to control packet memory, these values should be
	// aligned.
	if IdealBatchSize != conn.IdealBatchSize {
		t.Fatalf("IdealBatchSize: %d != conn.IdealBatchSize(): %d", IdealBatchSize, conn.IdealBatchSize)
	}
}

func makeControlMsg(cmsgLevel, cmsgType int32, dataLen int) []byte {
	msgLen := unix.CmsgSpace(dataLen)
	msg := make([]byte, msgLen)
	hdr2 := (*unix.Cmsghdr)(unsafe.Pointer(&msg[0]))
	hdr2.Level = cmsgLevel
	hdr2.Type = cmsgType
	hdr2.SetLen(unix.CmsgLen(dataLen))
	return msg
}

func gsoControl(gso uint16) []byte {
	msg := makeControlMsg(unix.SOL_UDP, unix.UDP_GRO, 2)
	binary.NativeEndian.PutUint16(msg[unix.SizeofCmsghdr:], gso)
	return msg
}

func rxqOverflowsControl(count uint32) []byte {
	msg := makeControlMsg(unix.SOL_SOCKET, unix.SO_RXQ_OVFL, 4)
	binary.NativeEndian.PutUint32(msg[unix.SizeofCmsghdr:], count)
	return msg
}

func Test_getRXQOverflowsMetric(t *testing.T) {
	c := qt.New(t)
	m := getRXQOverflowsMetric("")
	c.Assert(m, qt.IsNil)
	m = getRXQOverflowsMetric("rxq_overflows")
	c.Assert(m, qt.IsNotNil)
	wantM := getRXQOverflowsMetric("rxq_overflows")
	c.Assert(m, qt.Equals, wantM)
	uniq := getRXQOverflowsMetric("rxq_overflows_uniq")
	c.Assert(m, qt.Not(qt.Equals), uniq)
}

func Test_getRXQOverflowsFromControl(t *testing.T) {
	malformedControlMsg := gsoControl(1)
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&malformedControlMsg[0]))
	hdr.SetLen(1)

	tests := []struct {
		name    string
		control []byte
		want    uint32
		wantErr bool
	}{
		{
			name:    "malformed",
			control: malformedControlMsg,
			want:    0,
			wantErr: true,
		},
		{
			name:    "gso",
			control: gsoControl(1),
			want:    0,
			wantErr: false,
		},
		{
			name:    "rxq-overflows",
			control: rxqOverflowsControl(1),
			want:    1,
			wantErr: false,
		},
		{
			name:    "multiple-cmsg-rxq-overflows-at-head",
			control: append(rxqOverflowsControl(1), gsoControl(1)...),
			want:    1,
			wantErr: false,
		},
		{
			name:    "multiple-cmsg-rxq-overflows-at-tail",
			control: append(gsoControl(1), rxqOverflowsControl(1)...),
			want:    1,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getRXQOverflowsFromControl(tt.control)
			if (err != nil) != tt.wantErr {
				t.Errorf("getRXQOverflowsFromControl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getRXQOverflowsFromControl() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getGSOSizeFromControl(t *testing.T) {
	malformedControlMsg := gsoControl(1)
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&malformedControlMsg[0]))
	hdr.SetLen(1)

	tests := []struct {
		name    string
		control []byte
		want    int
		wantErr bool
	}{
		{
			name:    "malformed",
			control: malformedControlMsg,
			want:    0,
			wantErr: true,
		},
		{
			name:    "gso",
			control: gsoControl(1),
			want:    1,
			wantErr: false,
		},
		{
			name:    "rxq-overflows",
			control: rxqOverflowsControl(1),
			want:    0,
			wantErr: false,
		},
		{
			name:    "multiple-cmsg-gso-at-tail",
			control: append(rxqOverflowsControl(1), gsoControl(1)...),
			want:    1,
			wantErr: false,
		},
		{
			name:    "multiple-cmsg-gso-at-head",
			control: append(gsoControl(1), rxqOverflowsControl(1)...),
			want:    1,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getGSOSizeFromControl(tt.control)
			if (err != nil) != tt.wantErr {
				t.Errorf("getGSOSizeFromControl() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getGSOSizeFromControl() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_linuxBatchingConn_handleRXQOverflowCounter(t *testing.T) {
	c := qt.New(t)
	conn := &linuxBatchingConn{
		rxqOverflowsMetric: getRXQOverflowsMetric("test_handleRXQOverflowCounter"),
	}
	conn.rxqOverflowsMetric.Set(0) // test count > 1 will accumulate, reset

	// n == 0
	conn.handleRXQOverflowCounter([]ipv6.Message{{}}, 0, nil)
	c.Assert(conn.rxqOverflowsMetric.Value(), qt.Equals, int64(0))

	// rxErr non-nil
	conn.handleRXQOverflowCounter([]ipv6.Message{{}}, 0, io.EOF)
	c.Assert(conn.rxqOverflowsMetric.Value(), qt.Equals, int64(0))

	// nonzero counter
	control := rxqOverflowsControl(1)
	conn.handleRXQOverflowCounter([]ipv6.Message{{
		OOB: control,
		NN:  len(control),
	}}, 1, nil)
	c.Assert(conn.rxqOverflowsMetric.Value(), qt.Equals, int64(1))

	// nonzero counter, no change
	conn.handleRXQOverflowCounter([]ipv6.Message{{
		OOB: control,
		NN:  len(control),
	}}, 1, nil)
	c.Assert(conn.rxqOverflowsMetric.Value(), qt.Equals, int64(1))

	// counter rollover
	control = rxqOverflowsControl(0)
	conn.handleRXQOverflowCounter([]ipv6.Message{{
		OOB: control,
		NN:  len(control),
	}}, 1, nil)
	c.Assert(conn.rxqOverflowsMetric.Value(), qt.Equals, int64(1+math.MaxUint32))
}
