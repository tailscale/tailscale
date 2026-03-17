// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package batching

import (
	"encoding/binary"
	"io"
	"math"
	"net"
	"testing"
	"unsafe"

	qt "github.com/frankban/quicktest"
	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
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
			name: "second last split last empty",
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
			name: "second last no split last empty",
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
			name: "second last no split last no split",
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
			name: "second last no split last split",
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
			name: "second last split last split",
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
			name: "second last no split last split overflow",
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
	c := &linuxBatchingConn{}

	withGeneveSpace := func(len, cap int) []byte {
		return make([]byte, len+packet.GeneveFixedHeaderLength, cap+packet.GeneveFixedHeaderLength)
	}

	geneve := packet.GeneveHeader{
		Protocol: packet.GeneveProtocolWireGuard,
	}
	geneve.VNI.Set(1)

	cases := []struct {
		name     string
		buffs    [][]byte
		geneve   packet.GeneveHeader
		wantLens []int
		wantGSO  []int
	}{
		{
			name: "one message no coalesce",
			buffs: [][]byte{
				withGeneveSpace(1, 1),
			},
			wantLens: []int{1},
			wantGSO:  []int{0},
		},
		{
			name: "one message no coalesce vni.isSet",
			buffs: [][]byte{
				withGeneveSpace(1, 1),
			},
			geneve:   geneve,
			wantLens: []int{1 + packet.GeneveFixedHeaderLength},
			wantGSO:  []int{0},
		},
		{
			name: "two messages equal len coalesce",
			buffs: [][]byte{
				withGeneveSpace(1, 2),
				withGeneveSpace(1, 1),
			},
			wantLens: []int{2},
			wantGSO:  []int{1},
		},
		{
			name: "two messages equal len coalesce vni.isSet",
			buffs: [][]byte{
				withGeneveSpace(1, 2+packet.GeneveFixedHeaderLength),
				withGeneveSpace(1, 1),
			},
			geneve:   geneve,
			wantLens: []int{2 + (2 * packet.GeneveFixedHeaderLength)},
			wantGSO:  []int{1 + packet.GeneveFixedHeaderLength},
		},
		{
			name: "two messages unequal len coalesce",
			buffs: [][]byte{
				withGeneveSpace(2, 3),
				withGeneveSpace(1, 1),
			},
			wantLens: []int{3},
			wantGSO:  []int{2},
		},
		{
			name: "two messages unequal len coalesce vni.isSet",
			buffs: [][]byte{
				withGeneveSpace(2, 3+packet.GeneveFixedHeaderLength),
				withGeneveSpace(1, 1),
			},
			geneve:   geneve,
			wantLens: []int{3 + (2 * packet.GeneveFixedHeaderLength)},
			wantGSO:  []int{2 + packet.GeneveFixedHeaderLength},
		},
		{
			name: "three messages second unequal len coalesce",
			buffs: [][]byte{
				withGeneveSpace(2, 3),
				withGeneveSpace(1, 1),
				withGeneveSpace(2, 2),
			},
			wantLens: []int{3, 2},
			wantGSO:  []int{2, 0},
		},
		{
			name: "three messages second unequal len coalesce vni.isSet",
			buffs: [][]byte{
				withGeneveSpace(2, 3+(2*packet.GeneveFixedHeaderLength)),
				withGeneveSpace(1, 1),
				withGeneveSpace(2, 2),
			},
			geneve:   geneve,
			wantLens: []int{3 + (2 * packet.GeneveFixedHeaderLength), 2 + packet.GeneveFixedHeaderLength},
			wantGSO:  []int{2 + packet.GeneveFixedHeaderLength, 0},
		},
		{
			name: "three messages limited cap coalesce",
			buffs: [][]byte{
				withGeneveSpace(2, 4),
				withGeneveSpace(2, 2),
				withGeneveSpace(2, 2),
			},
			wantLens: []int{4, 2},
			wantGSO:  []int{2, 0},
		},
		{
			name: "three messages limited cap coalesce vni.isSet",
			buffs: [][]byte{
				withGeneveSpace(2, 4+packet.GeneveFixedHeaderLength),
				withGeneveSpace(2, 2),
				withGeneveSpace(2, 2),
			},
			geneve:   geneve,
			wantLens: []int{4 + (2 * packet.GeneveFixedHeaderLength), 2 + packet.GeneveFixedHeaderLength},
			wantGSO:  []int{2 + packet.GeneveFixedHeaderLength, 0},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			addr := &net.UDPAddr{
				IP:   net.ParseIP("127.0.0.1"),
				Port: 1,
			}
			msgs := make([]ipv6.Message, len(tt.buffs))
			for i := range msgs {
				msgs[i].Buffers = make([][]byte, 1)
				msgs[i].OOB = make([]byte, controlMessageSize)
			}
			got := c.coalesceMessages(addr, tt.geneve, tt.buffs, msgs, packet.GeneveFixedHeaderLength)
			if got != len(tt.wantLens) {
				t.Fatalf("got len %d want: %d", got, len(tt.wantLens))
			}
			for i := range got {
				if msgs[i].Addr != addr {
					t.Errorf("msgs[%d].Addr != passed addr", i)
				}
				gotLen := len(msgs[i].Buffers[0])
				if gotLen != tt.wantLens[i] {
					t.Errorf("len(msgs[%d].Buffers[0]) %d != %d", i, gotLen, tt.wantLens[i])
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
			name:    "rxq overflows",
			control: rxqOverflowsControl(1),
			want:    1,
			wantErr: false,
		},
		{
			name:    "multiple cmsg rxq overflows at head",
			control: append(rxqOverflowsControl(1), gsoControl(1)...),
			want:    1,
			wantErr: false,
		},
		{
			name:    "multiple cmsg rxq overflows at tail",
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
			name:    "rxq overflows",
			control: rxqOverflowsControl(1),
			want:    0,
			wantErr: false,
		},
		{
			name:    "multiple cmsg gso at tail",
			control: append(rxqOverflowsControl(1), gsoControl(1)...),
			want:    1,
			wantErr: false,
		},
		{
			name:    "multiple cmsg gso at head",
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
