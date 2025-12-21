// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package batching

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/tailscale/wireguard-go/conn"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
	"tailscale.com/net/packet"
)

func setGSOSize(control *[]byte, gsoSize uint16) {
	*control = (*control)[:cap(*control)]
	binary.LittleEndian.PutUint16(*control, gsoSize)
}

func getGSOSize(control []byte) (int, error) {
	if len(control) < 2 {
		return 0, nil
	}
	return int(binary.LittleEndian.Uint16(control)), nil
}

func Test_linuxBatchingConn_splitCoalescedMessages(t *testing.T) {
	c := &linuxBatchingConn{
		setGSOSizeInControl:   setGSOSize,
		getGSOSizeFromControl: getGSOSize,
	}

	newMsg := func(n, gso int) ipv6.Message {
		msg := ipv6.Message{
			Buffers: [][]byte{make([]byte, 1024)},
			N:       n,
			OOB:     make([]byte, 2),
		}
		binary.LittleEndian.PutUint16(msg.OOB, uint16(gso))
		if gso > 0 {
			msg.NN = 2
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
	c := &linuxBatchingConn{
		setGSOSizeInControl:   setGSOSize,
		getGSOSizeFromControl: getGSOSize,
	}

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
				msgs[i].OOB = make([]byte, 0, 2)
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
				gotGSO, err := getGSOSize(msgs[i].OOB)
				if err != nil {
					t.Fatalf("msgs[%d] getGSOSize err: %v", i, err)
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

func Test_getGSOSizeFromControl_MultipleMessages(t *testing.T) {
	// Test that getGSOSizeFromControl correctly parses UDP_GRO when it's not the first control message.
	const expectedGSOSize = 1420

	// First message: IP_TOS
	firstMsgLen := unix.CmsgSpace(1)
	firstMsg := make([]byte, firstMsgLen)
	hdr1 := (*unix.Cmsghdr)(unsafe.Pointer(&firstMsg[0]))
	hdr1.Level = unix.SOL_IP
	hdr1.Type = unix.IP_TOS
	hdr1.SetLen(unix.CmsgLen(1))
	firstMsg[unix.SizeofCmsghdr] = 0

	// Second message: UDP_GRO
	secondMsgLen := unix.CmsgSpace(2)
	secondMsg := make([]byte, secondMsgLen)
	hdr2 := (*unix.Cmsghdr)(unsafe.Pointer(&secondMsg[0]))
	hdr2.Level = unix.SOL_UDP
	hdr2.Type = unix.UDP_GRO
	hdr2.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(secondMsg[unix.SizeofCmsghdr:], expectedGSOSize)

	control := append(firstMsg, secondMsg...)

	gsoSize, err := getGSOSizeFromControl(control)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gsoSize != expectedGSOSize {
		t.Errorf("got GSO size %d, want %d", gsoSize, expectedGSOSize)
	}
}
