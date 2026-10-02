// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package derpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"expvar"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"tailscale.com/tstest"
	"tailscale.com/tsweb/varz"
	"tailscale.com/types/key"

	"golang.org/x/sys/unix"
)

// ipv4SYNWithMSS builds a raw IPv4+TCP SYN packet of the form returned by
// TCP_SAVED_SYN, with the given MSS.
func ipv4SYNWithMSS(mss uint16) []byte {
	pkt := make([]byte, 20+20+4)
	pkt[0] = 0x45 // IPv4, IHL=5 (20 bytes)
	pkt[9] = 6    // protocol: TCP
	// TCP header: data offset 6 (24 bytes, with 4 bytes of options).
	pkt[20+12] = 6 << 4
	// MSS option.
	opts := pkt[40:]
	opts[0] = 2 // kind: MSS
	opts[1] = 4 // length
	binary.BigEndian.PutUint16(opts[2:4], mss)
	return pkt
}

// ipv6SYNWithMSS builds a raw IPv6+TCP SYN packet with an MSS option.
func ipv6SYNWithMSS(mss uint16) []byte {
	pkt := make([]byte, 40+20+4)
	pkt[0] = 6 << 4 // IPv6
	pkt[6] = 6      // next header: TCP
	pkt[40+12] = 6 << 4
	opts := pkt[60:]
	opts[0] = 2
	opts[1] = 4
	binary.BigEndian.PutUint16(opts[2:4], mss)
	return pkt
}

func TestMSSFromSavedSyn(t *testing.T) {
	tests := []struct {
		name    string
		pkt     []byte
		want    uint16
		wantErr bool
	}{
		{
			name: "ipv4",
			pkt:  ipv4SYNWithMSS(1460),
			want: 1460,
		},
		{
			name: "ipv6",
			pkt:  ipv6SYNWithMSS(1440),
			want: 1440,
		},
		{
			name: "ipv4-options",
			pkt: func() []byte {
				pkt := ipv4SYNWithMSS(1400)
				pkt[0] = 0x46 // IHL=6: four bytes of IPv4 options
				return append(append(pkt[:20:20], 1, 1, 0, 0), pkt[20:]...)
			}(),
			want: 1400,
		},
		{
			name: "trailing-malformed-option",
			pkt: func() []byte {
				pkt := ipv4SYNWithMSS(1460)
				copy(pkt[40:], []byte{1, 1, 1, 2})
				return pkt
			}(),
			wantErr: true,
		},
		{
			name: "ipv4-with-nops-before-mss",
			pkt: func() []byte {
				pkt := make([]byte, 20+20+8)
				pkt[0] = 0x45
				pkt[9] = 6
				pkt[20+12] = 7 << 4 // data offset 7 (28 bytes: 20 + 8 options)
				opts := pkt[40:48]
				opts[0] = 1 // no-op
				opts[1] = 1 // no-op
				opts[2] = 2 // MSS
				opts[3] = 4
				binary.BigEndian.PutUint16(opts[4:6], 1400)
				return pkt
			}(),
			want: 1400,
		},
		{
			name: "ipv4-no-mss-option",
			pkt: func() []byte {
				pkt := make([]byte, 20+20)
				pkt[0] = 0x45
				pkt[9] = 6
				pkt[20+12] = 5 << 4 // no options at all
				return pkt
			}(),
			wantErr: true,
		},
		{
			name:    "truncated",
			pkt:     []byte{0x40, 0x00},
			wantErr: true,
		},
		{
			name: "not-tcp",
			pkt: func() []byte {
				pkt := ipv4SYNWithMSS(1460)
				pkt[9] = 17 // UDP
				return pkt
			}(),
			wantErr: true,
		},
		{
			name:    "bad-ip-version",
			pkt:     make([]byte, 60),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mssFromSavedSyn(tt.pkt)
			if (err != nil) != tt.wantErr {
				t.Fatalf("mssFromSavedSyn() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("mssFromSavedSyn() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestRecordSavedSynDisabled verifies that recordSavedSyn is a no-op when the
// server does not have TCP_SAVE_SYN recording enabled.
func TestRecordSavedSynDisabled(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()
	s.SetTCPSaveSyn(true)
	s.SetTCPSaveSyn(false)
	c := &sclient{s: s}
	c.recordSavedSyn()
	if got := s.tcpSavedSynStatus.String(); got != "{}" {
		t.Errorf("status map = %q, want empty", got)
	}
	if got := s.tcpSavedSynMSS.String(); !strings.Contains(got, `"count": 0`) {
		t.Errorf("MSS histogram = %q, want no observations", got)
	}
}

// TestRecordSavedSynIntegration verifies the full TCP_SAVE_SYN flow over a
// real kernel TCP connection: TCP_SAVE_SYN set on the listening socket via
// net.ListenConfig.Control (as cmd/derper does), inherited by the accepted
// connection, the client's SYN packet recovered with TCP_SAVED_SYN, and the
// client's advertised MSS recorded to the histogram.
func TestRecordSavedSynIntegration(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	s.SetTCPSaveSyn(true)
	defer s.Close()

	// Listen with TCP_SAVE_SYN set in the socket's Control hook, like
	// cmd/derper does with --tcp-save-syn. Accepted connections inherit
	// the option.
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			if e := c.Control(func(fd uintptr) {
				err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 1)
			}); e != nil {
				return e
			}
			return err
		},
	}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	tc := newWriterTestClient(t, s, ln)
	defer tc.close()

	// Wait for the client's run loop to fetch its saved SYN and record
	// the MSS. The client connected over loopback, where the kernel
	// advertises a very large MSS, so it lands in the +Inf bucket, but
	// don't depend on the kernel's choice of MSS.
	for deadline := time.Now().Add(10 * time.Second); ; {
		if st := s.tcpSavedSynStatus.Get("ok"); st != nil && st.Value() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("saved SYN never recorded; status = %s, MSS = %s", s.tcpSavedSynStatus.String(), s.tcpSavedSynMSS.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.tcpSavedSynMSS.String(); !strings.Contains(got, `"count": 1`) {
		t.Errorf("MSS histogram = %s; want one observation for a loopback client", got)
	}
}

// Connections without a saved SYN are counted separately from parse errors.
func TestRecordSavedSynNotSaved(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	s.SetTCPSaveSyn(true)
	defer s.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	peer, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := &sclient{s: s, nc: conn}
	c.recordSavedSyn()
	if got := s.tcpSavedSynStatus.Get("not-saved").Value(); got != 1 {
		t.Fatalf("not-saved = %d, want 1; status = %s", got, s.tcpSavedSynStatus.String())
	}
}

func TestRecordSavedSynDisableConcurrent(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()
	c := &sclient{s: s}
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			s.SetTCPSaveSyn(true)
			s.SetTCPSaveSyn(false)
		}
	})
	wg.Go(func() {
		for range 1000 {
			c.recordSavedSyn()
		}
	})
	wg.Wait()
	s.SetTCPSaveSyn(false)
	before := s.tcpSavedSynStatus.String()
	c.recordSavedSyn()
	if got := s.tcpSavedSynStatus.String(); got != before {
		t.Fatalf("disabled collection changed status: %s -> %s", before, got)
	}
}

func BenchmarkRecordSavedSynDisabled(b *testing.B) {
	s := New(key.NewNode(), b.Logf)
	defer s.Close()
	c := &sclient{s: s}
	b.ReportAllocs()
	for b.Loop() {
		c.recordSavedSyn()
	}
}

func TestSavedSynIPv6NextHeader(t *testing.T) {
	for _, next := range []byte{0, 43, 44, 50, 51, 60, 135, 17, 59} {
		t.Run(fmt.Sprint(next), func(t *testing.T) {
			pkt := ipv6SYNWithMSS(1440)
			pkt[6] = next
			_, err := mssFromSavedSyn(pkt)
			if err == nil {
				t.Fatal("unexpected success")
			}
			wantUnsupported := next != 17 && next != 59
			if errors.Is(err, errSavedSynIPv6Extension) != wantUnsupported {
				t.Fatalf("error = %v, want unsupported = %v", err, wantUnsupported)
			}
		})
	}
}

func TestSavedSynErrorLogRate(t *testing.T) {
	var logs int
	s := New(key.NewNode(), func(string, ...any) { logs++ })
	defer s.Close()
	clock := tstest.NewClock(tstest.ClockOpts{Start: time.Unix(12345, 0)})
	s.clock = clock
	logErrors := func() {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for range 100 {
			wg.Go(func() {
				<-start
				s.logSavedSynError("parsing", errors.New("bad packet"))
			})
		}
		close(start)
		wg.Wait()
	}
	logErrors()
	if logs != 1 {
		t.Fatalf("logs = %d, want 1", logs)
	}
	first := s.savedSynNextErrorLog.Load()
	if first != clock.Now().Add(10*time.Minute).UnixNano() {
		t.Fatalf("next error timestamp = %d, want %d", first, clock.Now().Add(10*time.Minute).UnixNano())
	}
	clock.Advance(10*time.Minute - time.Nanosecond)
	s.logSavedSynError("fetching", errors.New("kernel error"))
	if logs != 1 {
		t.Fatalf("logs before interval = %d, want 1", logs)
	}
	if s.savedSynNextErrorLog.Load() != first {
		t.Fatal("suppressed error changed timestamp")
	}
	clock.Advance(time.Nanosecond)
	logErrors()
	if logs != 2 {
		t.Fatalf("logs after interval = %d, want 2", logs)
	}
	if got := s.savedSynNextErrorLog.Load(); got != clock.Now().Add(10*time.Minute).UnixNano() {
		t.Fatalf("next error timestamp = %d, want %d", got, clock.Now().Add(10*time.Minute).UnixNano())
	}
}

func TestSavedSynErrorLogAtEpoch(t *testing.T) {
	var logs int
	s := New(key.NewNode(), func(string, ...any) { logs++ })
	defer s.Close()
	s.clock = tstest.NewClock(tstest.ClockOpts{Start: time.Unix(0, 0)})
	for range 2 {
		s.logSavedSynError("parsing", errors.New("bad packet"))
	}
	if logs != 1 {
		t.Fatalf("logs = %d, want 1", logs)
	}
}

func TestSavedSynMSSHistogram(t *testing.T) {
	s := New(key.NewNode(), t.Logf)
	defer s.Close()
	s.tcpSavedSynMSS.Observe(1400)
	s.tcpSavedSynMSS.Observe(1460)
	var out strings.Builder
	varz.WritePrometheusExpvar(&out, expvar.KeyValue{Key: "derp", Value: s.ExpVar(false)})
	for _, want := range []string{
		"# TYPE tcp_saved_syn_mss histogram",
		`tcp_saved_syn_mss_bucket{le="1400"} 1`,
		`tcp_saved_syn_mss_bucket{le="1460"} 2`,
		`tcp_saved_syn_mss_bucket{le="+Inf"} 2`,
		"tcp_saved_syn_mss_count 2",
		"tcp_saved_syn_mss_sum 2860",
	} {
		want = strings.ReplaceAll(want, "tcp_saved_syn_mss", "derp_tcp_saved_syn_mss")
		if !strings.Contains(out.String(), want) {
			t.Errorf("histogram missing %q: %s", want, out.String())
		}
	}
}

func FuzzMSSFromSavedSyn(f *testing.F) {
	f.Add(ipv4SYNWithMSS(1460))
	f.Add(ipv6SYNWithMSS(1440))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		mssFromSavedSyn(pkt)
	})
}
