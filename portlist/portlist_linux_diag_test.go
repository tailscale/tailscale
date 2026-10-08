// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package portlist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func diagTestMessage(typ, flags uint16, seq, pid uint32, body []byte) []byte {
	mlen := unix.NLMSG_HDRLEN + len(body)
	b := make([]byte, (mlen+3)&^3)
	binary.NativeEndian.PutUint32(b[0:4], uint32(mlen))
	binary.NativeEndian.PutUint16(b[4:6], typ)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	binary.NativeEndian.PutUint32(b[12:16], pid)
	copy(b[unix.NLMSG_HDRLEN:], body)
	return b
}

func diagTestRecord(family uint8) []byte {
	b := make([]byte, 72)
	b[0] = family
	return b
}

func TestParseDiagDatagramFaults(t *testing.T) {
	const seq, pid = 41, 99
	record := diagTestMessage(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI, seq, pid, diagTestRecord(unix.AF_INET))
	done := diagTestMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, seq, pid, nil)
	nonzeroPad := diagTestMessage(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI, seq, pid, []byte{unix.AF_INET, 0, 0, 0, 1})
	nonzeroPad[len(nonzeroPad)-1] = 7
	badLen := append([]byte(nil), done...)
	binary.NativeEndian.PutUint32(badLen[:4], uint32(len(badLen)+4))
	completionErr := diagTestMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, seq, pid, []byte{1, 0, 0, 0})

	tests := []struct {
		name       string
		datagram   []byte
		family     uint8
		wantDone   bool
		wantErr    bool
		wantRecord int
	}{
		{"valid_multipart_and_done", append(record, done...), unix.AF_INET, true, false, 1},
		{"record_without_done", record, unix.AF_INET, false, false, 1},
		{"interrupted_record", diagTestMessage(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, seq, pid, diagTestRecord(unix.AF_INET)), unix.AF_INET, false, true, 0},
		{"interrupted_done", diagTestMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, seq, pid, nil), unix.AF_INET, false, true, 0},
		{"nonzero_error", diagTestMessage(unix.NLMSG_ERROR, 0, seq, pid, []byte{0xff, 0xff, 0xff, 0xff}), unix.AF_INET, false, true, 0},
		{"zero_error_ack", diagTestMessage(unix.NLMSG_ERROR, 0, seq, pid, []byte{0, 0, 0, 0}), unix.AF_INET, false, true, 0},
		{"completion_error", completionErr, unix.AF_INET, false, true, 0},
		{"bad_sequence", diagTestMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, seq+1, pid, nil), unix.AF_INET, false, true, 0},
		{"bad_pid", diagTestMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, seq, pid+1, nil), unix.AF_INET, false, true, 0},
		{"bad_family", diagTestMessage(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI, seq, pid, diagTestRecord(unix.AF_INET6)), unix.AF_INET, false, true, 0},
		{"short_header", []byte{1, 2, 3}, unix.AF_INET, false, true, 0},
		{"length_exceeds_datagram", badLen, unix.AF_INET, false, true, 0},
		{"short_record", diagTestMessage(unix.SOCK_DIAG_BY_FAMILY, unix.NLM_F_MULTI, seq, pid, []byte{unix.AF_INET}), unix.AF_INET, false, true, 0},
		{"missing_alignment_padding", func() []byte {
			b := diagTestMessage(unix.NLMSG_DONE, unix.NLM_F_MULTI, seq, pid, []byte{1})
			return b[:len(b)-3]
		}(), unix.AF_INET, false, true, 0},
		{"nonzero_alignment_padding", nonzeroPad, unix.AF_INET, false, true, 0},
		{"data_after_done", append(done, record...), unix.AF_INET, false, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRecords := 0
			gotDone, err := parseDiagDatagram(tt.datagram, seq, pid, tt.family, func([]byte) error {
				gotRecords++
				return nil
			})
			if gotDone != tt.wantDone || (err != nil) != tt.wantErr || gotRecords != tt.wantRecord {
				t.Fatalf("got done=%v err=%v records=%d; want done=%v err=%v records=%d", gotDone, err, gotRecords, tt.wantDone, tt.wantErr, tt.wantRecord)
			}
		})
	}

	callbackErr := errors.New("callback failed")
	_, err := parseDiagDatagram(record, seq, pid, unix.AF_INET, func([]byte) error { return callbackErr })
	if !errors.Is(err, callbackErr) {
		t.Fatalf("callback error = %v, want %v", err, callbackErr)
	}
}

func TestDiagNetlinkErrnoIsTyped(t *testing.T) {
	const seq, pid = 41, 99
	for _, errno := range []unix.Errno{unix.EPERM, unix.ENOENT} {
		for _, typ := range []uint16{unix.NLMSG_ERROR, unix.NLMSG_DONE} {
			t.Run(fmt.Sprintf("errno=%d/type=%d", errno, typ), func(t *testing.T) {
				body := make([]byte, 4)
				code := -int32(errno)
				binary.NativeEndian.PutUint32(body, uint32(code))
				msg := diagTestMessage(typ, unix.NLM_F_MULTI, seq, pid, body)
				_, err := parseDiagDatagram(msg, seq, pid, unix.AF_INET, nil)
				if !errors.Is(err, errno) {
					t.Fatalf("error = %v, want %v", err, errno)
				}
				// In particular, a terminal ENOENT from a missing UDP handler
				// must disable diagnostics rather than retry on every poll.
				if !isDiagCapabilityError(err) {
					t.Fatalf("error = %v, not classified as a capability failure", err)
				}
			})
		}
	}
}

func TestDiagCapabilityErrorClassification(t *testing.T) {
	for _, errno := range []unix.Errno{unix.ENOENT, unix.EPERM, unix.EACCES, unix.EAFNOSUPPORT, unix.EPROTONOSUPPORT, unix.ENOPROTOOPT, unix.EINVAL, unix.ENOSYS} {
		if !isDiagCapabilityError(fmt.Errorf("wrapped: %w", errno)) {
			t.Errorf("%v was not classified as a capability error", errno)
		}
	}
	if isDiagCapabilityError(fmt.Errorf("wrapped: %w", unix.EIO)) {
		t.Error("EIO was classified as a capability error")
	}
}

func TestDiagRequestTCPListenEncoding(t *testing.T) {
	b := diagRequest(unix.AF_INET, unix.IPPROTO_TCP)
	if len(b) != 56 {
		t.Fatalf("request length = %d, want 56", len(b))
	}
	// inet_diag_req_v2.idiag_states is a native-endian u32. TCP_LISTEN is
	// state 10, so TCPF_LISTEN is 1<<10 (0x400).
	want := []byte{unix.AF_INET, unix.IPPROTO_TCP, 0, 0, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(want[4:], 1<<tcpListen)
	if diff := cmp.Diff(b[:8], want); diff != "" {
		t.Fatalf("unexpected TCP request header (-got +want):\n%s", diff)
	}
}

func TestDiagLoopbackHelpers(t *testing.T) {
	v4 := make([]byte, 16)
	v4[0], v4[3] = 127, 1
	if !isDiagV4Localhost(v4, unix.AF_INET) {
		t.Fatal("127.0.0.1 must be recognized as IPv4 localhost")
	}
	v4[3] = 2
	if isDiagV4Localhost(v4, unix.AF_INET) {
		t.Fatal("127.0.0.2 must not be recognized as IPv4 localhost")
	}
	v6 := make([]byte, 16)
	v6[15] = 1
	if !isDiagV6Localhost(v6, unix.AF_INET6) {
		t.Fatal("::1 must be recognized as IPv6 localhost")
	}
	v6[14] = 1
	if isDiagV6Localhost(v6, unix.AF_INET6) {
		t.Fatal("non ::1 IPv6 address recognized as localhost")
	}
}
