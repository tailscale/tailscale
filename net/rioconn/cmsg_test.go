// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package rioconn

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
	"unsafe"
)

func TestControlMessagesSize(t *testing.T) {
	t.Parallel()
	if gotSize := unsafe.Sizeof(controlMessages{}); gotSize != controlMessagesSize {
		t.Errorf("got: %d; want %d", gotSize, controlMessagesSize)
	}
}

func TestControlMessageAppend(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		clear     bool // whether to call Clear() before appending
		messages  []controlMessage
		wantBytes []byte
	}{
		{
			name:      "zero",
			wantBytes: []byte{},
		},
		{
			name:  "clear",
			clear: true,
			wantBytes: chooseForArch(
				[]byte{
					0x04, 0x00, 0x00, 0x00, // TotalLength = 4 (_RIO_CMSG_BASE_SIZE)
					// no padding needed on 32-bit platforms
				},
				[]byte{
					0x08, 0x00, 0x00, 0x00, // TotalLength = 8 (_RIO_CMSG_BASE_SIZE)
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
				},
			),
		},
		{
			name: "single",
			messages: []controlMessage{
				{Level: 15, Type: 42, Data: []byte{0xAA, 0xBB, 0xCC}},
			},
			wantBytes: chooseForArch(
				[]byte{
					0x14, 0x00, 0x00, 0x00, // TotalLength = 20 (_RIO_CMSG_BASE_SIZE + aligned cmsg size)
					0x0F, 0x00, 0x00, 0x00, // cmsg Len = 15  (excluding padding)
					0x0F, 0x00, 0x00, 0x00, // cmsg Level = 15
					0x2A, 0x00, 0x00, 0x00, // cmsg Type = 42
					0xAA, 0xBB, 0xCC, // cmsg Data
					0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
				},
				[]byte{
					0x20, 0x00, 0x00, 0x00, // TotalLength = 32 (_RIO_CMSG_BASE_SIZE + aligned cmsg size)
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
					0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cmsg Len = 19 (excluding padding)
					0x0F, 0x00, 0x00, 0x00, // cmsg Level = 15
					0x2A, 0x00, 0x00, 0x00, // cmsg Type = 42
					0xAA, 0xBB, 0xCC, // cmsg Data
					0x00, 0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
				},
			),
		},
		{
			name:  "single/after-clear",
			clear: true,
			messages: []controlMessage{
				{Level: 15, Type: 42, Data: []byte{0xAA, 0xBB, 0xCC}},
			},
			wantBytes: chooseForArch(
				[]byte{ // same as "single" test case
					0x14, 0x00, 0x00, 0x00,
					0x0F, 0x00, 0x00, 0x00,
					0x0F, 0x00, 0x00, 0x00,
					0x2A, 0x00, 0x00, 0x00,
					0xAA, 0xBB, 0xCC,
					0x00,
				},
				[]byte{ // same as "single" test case
					0x20, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00,
					0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x0F, 0x00, 0x00, 0x00,
					0x2A, 0x00, 0x00, 0x00,
					0xAA, 0xBB, 0xCC,
					0x00, 0x00, 0x00, 0x00, 0x00,
				},
			),
		},
		{
			name: "multiple",
			messages: []controlMessage{
				{Level: 1, Type: 2, Data: []byte{
					0xAA, 0xBB, 0xCC, 0xDD,
				}},
				{Level: 3, Type: 4, Data: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				}},
			},
			wantBytes: chooseForArch(
				[]byte{
					0x30, 0x00, 0x00, 0x00, // TotalLength = 48 (_RIO_CMSG_BASE_SIZE + aligned cmsg1 size + aligned cmsg2 size)
					// cmsg 1
					0x10, 0x00, 0x00, 0x00, // cmsg Len = 16
					0x01, 0x00, 0x00, 0x00, // cmsg Level = 1
					0x02, 0x00, 0x00, 0x00, // cmsg Type = 2
					0xAA, 0xBB, 0xCC, 0xDD, // cmsg Data
					// cmsg 2
					0x1C, 0x00, 0x00, 0x00, // cmsg Len = 28
					0x03, 0x00, 0x00, 0x00, // cmsg Level = 3
					0x04, 0x00, 0x00, 0x00, // cmsg Type = 4
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				},
				[]byte{
					0x40, 0x00, 0x00, 0x00, // TotalLength = 64 (_RIO_CMSG_BASE_SIZE + aligned cmsg1 size + aligned cmsg2 size)
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
					// cmsg 1
					0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cmsg Len = 20 (excluding padding)
					0x01, 0x00, 0x00, 0x00, // cmsg Level = 1
					0x02, 0x00, 0x00, 0x00, // cmsg Type = 2
					0xAA, 0xBB, 0xCC, 0xDD, // cmsg Data
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
					// cmsg 2
					0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cmsg Len = 32
					0x03, 0x00, 0x00, 0x00, // cmsg Level = 3
					0x04, 0x00, 0x00, 0x00, // cmsg Type = 4
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // cmsg Data
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				},
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var cmsgs controlMessages
			if tt.clear {
				cmsgs.Clear()
			}
			for _, cm := range tt.messages {
				if err := cmsgs.Append(cm.Level, cm.Type, cm.Data); err != nil {
					t.Fatalf("Append failed: %v", err)
				}
			}

			if gotBytes := cmsgs.Bytes(); !bytes.Equal(gotBytes, tt.wantBytes) {
				t.Fatalf("buffer bytes:\ngot\n%v\nwant\n%v",
					hex.Dump(gotBytes), hex.Dump(tt.wantBytes),
				)
			}
		})
	}
}

func TestControlMessageAppendNotEnoughSpace(t *testing.T) {
	t.Parallel()
	var cmsgs controlMessages
	if err := cmsgs.Append(1, 2, bytes.Repeat([]byte{0xCC}, 1024)); err == nil {
		t.Errorf("Append succeeded unexpectedly")
	}
	if cmsgs.totalLength > uint32(_RIO_CMSG_BASE_SIZE) {
		t.Errorf("Unexpected TotalLength after failed Append: %d", cmsgs.totalLength)
	}
}

func TestControlMessageIterator(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		bytes        []byte
		wantMessages []controlMessage
	}{
		{
			name:         "zero",
			bytes:        []byte{},
			wantMessages: []controlMessage{},
		},
		{
			name: "empty",
			bytes: chooseForArch(
				[]byte{
					0x04, 0x00, 0x00, 0x00, // TotalLength = 4 (_RIO_CMSG_BASE_SIZE)
				},
				[]byte{
					0x08, 0x00, 0x00, 0x00, // TotalLength = 8 (_RIO_CMSG_BASE_SIZE)
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
				},
			),
			wantMessages: []controlMessage{},
		},
		{
			name: "single",
			bytes: chooseForArch(
				[]byte{
					0x14, 0x00, 0x00, 0x00, // TotalLength = 20 (_RIO_CMSG_BASE_SIZE + aligned cmsg size)
					0x0F, 0x00, 0x00, 0x00, // cmsg Len = 15 (excluding padding)
					0x0F, 0x00, 0x00, 0x00, // cmsg Level = 15
					0x2A, 0x00, 0x00, 0x00, // cmsg Type = 42
					0xAA, 0xBB, 0xCC, // cmsg Data
					0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
				},
				[]byte{
					0x20, 0x00, 0x00, 0x00, // TotalLength = 32 (_RIO_CMSG_BASE_SIZE + aligned cmsg size)
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
					0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cmsg Len = 19 (excluding padding)
					0x0F, 0x00, 0x00, 0x00, // cmsg Level = 15
					0x2A, 0x00, 0x00, 0x00, // cmsg Type = 42
					0xAA, 0xBB, 0xCC, // cmsg Data
					0x00, 0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
				},
			),
			wantMessages: []controlMessage{
				{Level: 15, Type: 42, Data: []byte{
					0xAA, 0xBB, 0xCC,
				}},
			},
		},
		{
			name: "multiple",
			bytes: chooseForArch(
				[]byte{
					0x30, 0x00, 0x00, 0x00, // TotalLength = 48 (_RIO_CMSG_BASE_SIZE + aligned cmsg1 size + aligned cmsg2 size)
					// cmsg 1
					0x10, 0x00, 0x00, 0x00, // cmsg Len = 16
					0x01, 0x00, 0x00, 0x00, // cmsg Level = 1
					0x02, 0x00, 0x00, 0x00, // cmsg Type = 2
					0xAA, 0xBB, 0xCC, 0xDD, // cmsg Data
					// cmsg 2
					0x1C, 0x00, 0x00, 0x00, // cmsg Len = 28
					0x03, 0x00, 0x00, 0x00, // cmsg Level = 3
					0x04, 0x00, 0x00, 0x00, // cmsg Type = 4
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				},
				[]byte{
					0x40, 0x00, 0x00, 0x00, // TotalLength = 64 (_RIO_CMSG_BASE_SIZE + aligned cmsg1 size + aligned cmsg2 size)
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
					// cmsg 1
					0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cmsg Len = 20 (excluding padding)
					0x01, 0x00, 0x00, 0x00, // cmsg Level = 1
					0x02, 0x00, 0x00, 0x00, // cmsg Type = 2
					0xAA, 0xBB, 0xCC, 0xDD, // cmsg Data
					0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
					// cmsg 2
					0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cmsg Len = 32
					0x03, 0x00, 0x00, 0x00, // cmsg Level = 3
					0x04, 0x00, 0x00, 0x00, // cmsg Type = 4
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // cmsg Data
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				},
			),
			wantMessages: []controlMessage{
				{Level: 1, Type: 2, Data: []byte{
					0xAA, 0xBB, 0xCC, 0xDD,
				}},
				{Level: 3, Type: 4, Data: []byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
				}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var cmsgs controlMessages
			copy(cmsgs.Buffer(), tt.bytes)

			gotMessages := slices.Collect(cmsgs.All())
			if len(gotMessages) != len(tt.wantMessages) {
				t.Fatalf("number of messages: got %d; want %d", len(gotMessages), len(tt.wantMessages))
			}

			for i := range gotMessages {
				if got, want := gotMessages[i], tt.wantMessages[i]; got.Level != want.Level || got.Type != want.Type || !bytes.Equal(got.Data, want.Data) {
					t.Errorf("message %d:\ngot %v\nwant %v", i, got, want)
				}
			}
		})
	}
}

func TestControlMessageUInt32(t *testing.T) {
	t.Parallel()

	const (
		msgLvl  = 1
		msgType = 2
		msgVal  = uint32(0xAABBCCDD)
	)
	var cmsgs controlMessages
	if err := cmsgs.AppendUInt32(msgLvl, msgType, msgVal); err != nil {
		t.Fatalf("AppendUInt32 failed: %v", err)
	}
	wantBytes := chooseForArch(
		[]byte{
			0x14, 0x00, 0x00, 0x00, // TotalLength = 20 (_RIO_CMSG_BASE_SIZE + aligned cmsg size)
			0x10, 0x00, 0x00, 0x00, // cmsg Len = 16
			0x01, 0x00, 0x00, 0x00, // cmsg Level = 1
			0x02, 0x00, 0x00, 0x00, // cmsg Type = 2
			0xDD, 0xCC, 0xBB, 0xAA, // cmsg Data
		},
		[]byte{
			0x20, 0x00, 0x00, 0x00, // TotalLength = 32 (_RIO_CMSG_BASE_SIZE + aligned cmsg size)
			0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
			0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cmsg Len = 20 (excluding padding)
			0x01, 0x00, 0x00, 0x00, // cmsg Level = 1
			0x02, 0x00, 0x00, 0x00, // cmsg Type = 2
			0xDD, 0xCC, 0xBB, 0xAA, // cmsg Data
			0x00, 0x00, 0x00, 0x00, // padding to align to _WSA_CMSGHDR_ALIGNMENT
		},
	)
	if gotBytes := cmsgs.Bytes(); !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("buffer bytes:\ngot\n%v\nwant\n%v",
			hex.Dump(gotBytes), hex.Dump(wantBytes),
		)
	}
	gotVal, ok := cmsgs.GetUInt32Ok(msgLvl, msgType)
	if !ok {
		t.Fatal("GetUInt32Ok failed to find value")
	}
	if gotVal != msgVal {
		t.Fatalf("uint32: got 0x%X; want 0x%X", gotVal, msgVal)
	}
}

func TestControlMessageGetUInt32(t *testing.T) {
	t.Parallel()

	var cmsgs controlMessages
	if _, ok := cmsgs.GetUInt32Ok(1, 2); ok {
		t.Fatal("GetUInt32Ok found unexpected value")
	}
	cmsgs.AppendUInt32(3, 4, 0xDEADBEEF)
	if _, ok := cmsgs.GetUInt32Ok(1, 2); ok {
		t.Fatal("GetUInt32Ok found unexpected value")
	}
	if gotVal, ok := cmsgs.GetUInt32Ok(3, 4); !ok {
		t.Fatal("GetUInt32Ok found unexpected value")
	} else if gotVal != 0xDEADBEEF {
		t.Fatalf("GetUInt32Ok: got 0x%X; want 0xDEADBEEF", gotVal)
	}
}

func TestControlMessageNoAlloc(t *testing.T) {
	const (
		msgLvl  = 1
		msgType = 2
		msgVal  = uint32(0xAABBCCDD)
	)

	var cmsgs controlMessages
	allocs := testing.AllocsPerRun(1000, func() {
		cmsgs.Clear()
		cmsgs.AppendUInt32(msgLvl, msgType, msgVal)
	})
	if allocs != 0 {
		t.Fatalf("AppendUInt32 allocated %f times; want 0", allocs)
	}
	allocs = testing.AllocsPerRun(1000, func() {
		gotVal, ok := cmsgs.GetUInt32Ok(msgLvl, msgType)
		if !ok {
			t.Fatal("GetUInt32Ok failed to find value")
		}
		if gotVal != msgVal {
			t.Fatalf("GetUInt32Ok: got 0x%X; want 0x%X", gotVal, msgVal)
		}
	})
	if allocs != 0 {
		t.Fatalf("GetUInt32Ok allocated %f times; want 0", allocs)
	}
}

func BenchmarkControlMessagesAppendUInt32(b *testing.B) {
	var cmsgs controlMessages

	b.ReportAllocs()
	for b.Loop() {
		cmsgs.Clear()
		cmsgs.AppendUInt32(1, 2, uint32(3))
	}
}

func BenchmarkControlMessagesGetUInt32Ok(b *testing.B) {
	const (
		msgLvl  = 1
		msgType = 2
		msgVal  = uint32(0xAABBCCDD)
	)

	var cmsgs controlMessages
	cmsgs.AppendUInt32(msgLvl, msgType, msgVal)

	b.ReportAllocs()
	for b.Loop() {
		gotMsgVal, ok := cmsgs.GetUInt32Ok(msgLvl, msgType)
		if !ok {
			b.Fatal("GetUInt32Ok failed to find value")
		}
		if gotMsgVal != msgVal {
			b.Fatalf("GetUInt32Ok: got 0x%X; want 0x%X", gotMsgVal, msgVal)
		}
	}
}

func chooseForArch[T any](val32, val64 T) T {
	if unsafe.Sizeof(uintptr(0)) == 4 {
		return val32
	}
	return val64
}

// String returns a string representation of the control message.
func (cmsg controlMessage) String() string {
	return fmt.Sprintf("cmsg{Level=%d Type=%d}\n%s", cmsg.Level, cmsg.Type, hex.Dump(cmsg.Data))
}
