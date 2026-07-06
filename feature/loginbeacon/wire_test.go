// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBeaconRoundTrip(t *testing.T) {
	in := &beaconMsg{
		RequestID:    requestID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SenderEphPub: [32]byte{0xaa, 0xbb, 0xcc},
		UnixSec:      1_700_000_000,
		Hostname:     "kitchen-tv",
		DeviceKind:   "tvos",
		DeviceIDHash: [16]byte{0xff, 0xee, 0xdd},
	}
	pkt, err := marshalBeacon(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := parseBeacon(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if in.RequestID != out.RequestID ||
		in.SenderEphPub != out.SenderEphPub ||
		in.UnixSec != out.UnixSec ||
		in.Hostname != out.Hostname ||
		in.DeviceKind != out.DeviceKind ||
		in.DeviceIDHash != out.DeviceIDHash {
		t.Fatalf("beacon round-trip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestApprovalRoundTrip(t *testing.T) {
	in := &approvalMsg{
		RequestID:      requestID{9, 9, 9},
		ApproverEphPub: [32]byte{0x11, 0x22, 0x33},
		UnixSec:        1_700_000_042,
	}
	pkt := marshalApproval(in)
	out, err := parseApproval(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if in.RequestID != out.RequestID ||
		in.ApproverEphPub != out.ApproverEphPub ||
		in.UnixSec != out.UnixSec {
		t.Fatalf("approval round-trip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestSealedURLRoundTrip(t *testing.T) {
	in := &sealedURLMsg{
		RequestID:  requestID{7},
		Nonce:      [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Ciphertext: []byte("this is not real ciphertext but the codec doesn't care"),
	}
	pkt, err := marshalSealedURL(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := parseSealedURL(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if in.RequestID != out.RequestID || in.Nonce != out.Nonce || !bytes.Equal(in.Ciphertext, out.Ciphertext) {
		t.Fatalf("sealed round-trip mismatch:\nin:  %+v\nout: %+v", in, out)
	}
}

func TestHostnameTooLong(t *testing.T) {
	_, err := marshalBeacon(&beaconMsg{Hostname: strings.Repeat("x", maxHostname+1)})
	if !errors.Is(err, errBadHostname) {
		t.Fatalf("want errBadHostname, got %v", err)
	}
}

func TestParseHeaderRejectsBadMagic(t *testing.T) {
	pkt := make([]byte, headerSize)
	copy(pkt, "TSLBc")
	pkt[5] = 'X' // corrupt terminator
	pkt[6] = version
	pkt[7] = byte(msgTypeBeacon)
	if _, _, err := parseHeader(pkt); !errors.Is(err, errBadMagic) {
		t.Fatalf("want errBadMagic, got %v", err)
	}
}

func TestParseHeaderRejectsBadVersion(t *testing.T) {
	pkt := make([]byte, headerSize)
	copy(pkt, magic)
	pkt[6] = 0xff
	pkt[7] = byte(msgTypeBeacon)
	if _, _, err := parseHeader(pkt); !errors.Is(err, errBadVersion) {
		t.Fatalf("want errBadVersion, got %v", err)
	}
}

func TestParseHeaderRejectsBadType(t *testing.T) {
	pkt := make([]byte, headerSize)
	copy(pkt, magic)
	pkt[6] = version
	pkt[7] = 0xff
	if _, _, err := parseHeader(pkt); !errors.Is(err, errBadType) {
		t.Fatalf("want errBadType, got %v", err)
	}
}

func TestParseBeaconTruncated(t *testing.T) {
	pkt, err := marshalBeacon(&beaconMsg{Hostname: "abc", DeviceKind: "tv"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Chop the trailing device_id_hash.
	if _, err := parseBeacon(pkt[:len(pkt)-4]); !errors.Is(err, errBadLength) {
		t.Fatalf("want errBadLength, got %v", err)
	}
}

func FuzzParseAny(f *testing.F) {
	if pkt, err := marshalBeacon(&beaconMsg{Hostname: "a", DeviceKind: "b"}); err == nil {
		f.Add(pkt)
	}
	f.Add(marshalApproval(&approvalMsg{}))
	if pkt, err := marshalSealedURL(&sealedURLMsg{Ciphertext: []byte("x")}); err == nil {
		f.Add(pkt)
	}
	f.Fuzz(func(t *testing.T, buf []byte) {
		// parseHeader is called by every entrypoint; make sure it never
		// panics regardless of buf contents.
		t.Helper()
		if _, _, err := parseHeader(buf); err == nil {
			switch buf[7] {
			case byte(msgTypeBeacon):
				_, _ = parseBeacon(buf)
			case byte(msgTypeApproval):
				_, _ = parseApproval(buf)
			case byte(msgTypeSealedURL):
				_, _ = parseSealedURL(buf)
			}
		}
	})
}
