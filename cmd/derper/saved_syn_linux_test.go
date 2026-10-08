// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/ktimeout"
	"tailscale.com/types/key"
)

func TestTCPSaveSynListenConfig(t *testing.T) {
	old := *tcpSaveSyn
	*tcpSaveSyn = true
	t.Cleanup(func() { *tcpSaveSyn = old })
	lc := net.ListenConfig{Control: listenControlFunc()}
	httpLC := lc
	httpLC.Control = ktimeout.UserTimeout(*tcpUserTimeout)
	for _, tt := range []struct {
		name string
		lc   net.ListenConfig
		want int
	}{
		{"derp", lc, 1},
		{"port80", httpLC, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := tt.lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			raw, err := ln.(*net.TCPListener).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var got int
			var optErr error
			if err := raw.Control(func(fd uintptr) {
				got, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN)
			}); err != nil {
				t.Fatal(err)
			}
			if optErr != nil {
				t.Fatal(optErr)
			}
			if got != tt.want {
				t.Fatalf("TCP_SAVE_SYN = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSynRateMeasurement(t *testing.T) {
	var m synRateMeasurement
	now := time.Unix(12345, 0)
	for _, tt := range []struct {
		advance     time.Duration
		total, want float64
	}{
		{0, 100, 0},
		{time.Second, 1100, 1000},
		{2 * time.Second, 4100, 1500}, // elapsed time, not nominal timer interval
		{time.Second, 20016, 15916},
		{time.Second, 20016 + maxSavedSynRate, maxSavedSynRate},
		{time.Second, 20017 + 2*maxSavedSynRate, maxSavedSynRate + 1},
		{time.Second, 10, 0}, // counter reset
		{0, 10, 0},           // no elapsed time
		{time.Second, 10, 0}, // idle
	} {
		now = now.Add(tt.advance)
		if got := m.update(now, tt.total); got != tt.want {
			t.Errorf("update(%v, %v) = %v, want %v", now, tt.total, got, tt.want)
		}
	}
}

func newTestSavedSynListener(t *testing.T) *savedSynListener {
	t.Helper()
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		if e := c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN, 1)
		}); e != nil {
			return e
		}
		return err
	}}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	raw, err := ln.(*net.TCPListener).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	s := derpserver.New(key.NewNode(), t.Logf)
	s.SetTCPSaveSyn(true)
	t.Cleanup(func() { s.Close() })
	return &savedSynListener{Listener: ln, rawConn: raw, server: s}
}

func checkTCPSaveSyn(t *testing.T, ln *savedSynListener, want int) {
	t.Helper()
	var got int
	var optErr error
	if err := ln.rawConn.Control(func(fd uintptr) {
		got, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_SAVE_SYN)
	}); err != nil {
		t.Fatal(err)
	}
	if optErr != nil {
		t.Fatal(optErr)
	}
	if got != want {
		t.Fatalf("TCP_SAVE_SYN = %d, want %d", got, want)
	}
}

func TestSavedSynListenerUpdate(t *testing.T) {
	for _, failRead := range []bool{false, true} {
		name := "high-rate"
		if failRead {
			name = "read-error"
		}
		t.Run(name, func(t *testing.T) {
			var monitor synRateMonitor
			ln := newTestSavedSynListener(t)
			before := savedSynDisabled.Value()
			now := time.Unix(12345, 0)
			if failRead {
				monitor.update(ln, now, 0, errors.New("procfs unavailable"))
			} else {
				var total float64
				for _, rate := range []float64{0, 15916, maxSavedSynRate} {
					total += rate
					monitor.update(ln, now, total, nil)
					checkTCPSaveSyn(t, ln, 1)
					now = now.Add(time.Second)
				}
				monitor.update(ln, now, total+maxSavedSynRate+1, nil)
			}
			if !monitor.disabled {
				t.Fatal("saving not disabled")
			}
			checkTCPSaveSyn(t, ln, 0)
			raw := ln.rawConn
			ln.rawConn = nil
			monitor.update(ln, now.Add(time.Second), 0, nil)
			monitor.update(ln, now.Add(2*time.Second), 42, nil)
			if got := savedSynRate.Value(); got != 42 {
				t.Fatalf("rate after disabling = %v, want 42", got)
			}
			measurement := monitor.measurement
			monitor.update(ln, now.Add(3*time.Second), 0, errors.New("procfs unavailable"))
			if monitor.measurement != measurement {
				t.Fatal("failed read changed measurement")
			}
			monitor.update(ln, now.Add(4*time.Second), 42+2*(maxSavedSynRate+1), nil)
			if got := savedSynRate.Value(); got != maxSavedSynRate+1 {
				t.Fatalf("rate after disabling = %v, want %v", got, maxSavedSynRate+1)
			}
			ln.rawConn = raw
			checkTCPSaveSyn(t, ln, 0)
			if got := savedSynDisabled.Value() - before; got != 1 {
				t.Fatalf("disable count = %d, want 1", got)
			}
		})
	}
}

func TestSavedSynListenerDisableRetry(t *testing.T) {
	var monitor synRateMonitor
	ln := newTestSavedSynListener(t)
	ln.Listener.Close()
	now := time.Unix(12345, 0)
	monitor.update(ln, now, 0, errors.New("procfs unavailable"))
	if monitor.disabled || monitor.disableReason == nil {
		t.Fatal("failed disable was not left pending")
	}
	monitor.update(ln, now.Add(time.Second), 0, nil)
	if monitor.disabled || monitor.lastErrorLog != now {
		t.Fatal("failed retry changed disabled state or logged again")
	}
	replacement := newTestSavedSynListener(t)
	ln.rawConn = replacement.rawConn
	monitor.update(ln, now.Add(2*time.Second), 0, nil)
	if !monitor.disabled {
		t.Fatal("retry did not disable saving")
	}
	checkTCPSaveSyn(t, ln, 0)
}

func TestIncomingSYNs(t *testing.T) {
	var buf [64 << 10]byte
	if n, err := incomingSYNs(buf[:]); err != nil || n < 0 {
		t.Fatalf("incomingSYNs() = %v, %v", n, err)
	}
}

func BenchmarkIncomingSYNs(b *testing.B) {
	var buf [64 << 10]byte
	b.ReportAllocs()
	for b.Loop() {
		if _, err := incomingSYNs(buf[:]); err != nil {
			b.Fatal(err)
		}
	}
}

func TestParseProcNetCounters(t *testing.T) {
	for _, tt := range []struct {
		name, data string
		want       uint64
		wantErr    bool
	}{
		{"normal", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 12 34\n", 46, false},
		{"reordered", "TcpExt: Unknown ListenDrops SyncookiesSent\nTcpExt: junk 34 12", 46, false},
		{"other-protocols", "IpExt: Junk\nIpExt: junk\nTcpExt: SyncookiesSent ListenDrops\nTcpExt: 12 34\nIpExt: Junk\nIpExt: junk", 46, false},
		{"whitespace", "TcpExt:\tSyncookiesSent  ListenDrops\r\nTcpExt:  12\t34 \r\n", 46, false},
		{"zero", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 0 0", 0, false},
		{"uint64", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 18446744073709551615 0", ^uint64(0), false},
		{"missing-protocol", "IpExt: Junk\nIpExt: junk", 0, true},
		{"missing-counter", "TcpExt: SyncookiesSent\nTcpExt: 12", 0, true},
		{"duplicate-counter", "TcpExt: SyncookiesSent ListenDrops ListenDrops\nTcpExt: 12 34 56", 0, true},
		{"missing-values", "TcpExt: SyncookiesSent ListenDrops\n", 0, true},
		{"wrong-protocol", "TcpExt: SyncookiesSent ListenDrops\nIpExt: 12 34", 0, true},
		{"bad-prefix", "TcpExt:Bad SyncookiesSent ListenDrops\nTcpExt: 12 34", 0, true},
		{"short-values", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 12", 0, true},
		{"extra-values", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 12 34 56", 0, true},
		{"bad-number", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: junk 34", 0, true},
		{"negative", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: -1 34", 0, true},
		{"number-overflow", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 18446744073709551616 0", 0, true},
		{"sum-overflow", "TcpExt: SyncookiesSent ListenDrops\nTcpExt: 18446744073709551615 1", 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProcNetCounters([]byte(tt.data), "TcpExt:", "SyncookiesSent", "ListenDrops")
			if (err != nil) != tt.wantErr || err == nil && got != tt.want {
				t.Fatalf("parseProcNetCounters() = %d, %v; want %d, error = %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
	got, err := parseProcNetCounters([]byte("Tcp: Junk PassiveOpens\nTcp: junk 42"), "Tcp:", "PassiveOpens")
	if err != nil || got != 42 {
		t.Fatalf("PassiveOpens = %d, %v; want 42, nil", got, err)
	}
}

func TestReadProcNetCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snmp")
	data := "Tcp: PassiveOpens\nTcp: 42\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var buf [128]byte
	if got, err := readProcNetCounters(path, buf[:], "Tcp:", "PassiveOpens"); err != nil || got != 42 {
		t.Fatalf("readProcNetCounters() = %d, %v; want 42, nil", got, err)
	}
	if _, err := readProcNetCounters(path, buf[:len(data)-1], "Tcp:", "PassiveOpens"); err == nil {
		t.Fatal("accepted a snapshot exceeding the buffer size")
	}
	if _, err := readProcNetCounters(path+"-missing", buf[:], "Tcp:", "PassiveOpens"); err == nil {
		t.Fatal("accepted a missing file")
	}
}

func BenchmarkParseProcNetCounters(b *testing.B) {
	data := []byte("TcpExt: Unknown SyncookiesSent ListenDrops Other\nTcpExt: junk 12 34 junk\n")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseProcNetCounters(data, "TcpExt:", "SyncookiesSent", "ListenDrops"); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzParseProcNetCounters(f *testing.F) {
	f.Add([]byte("TcpExt: SyncookiesSent ListenDrops\nTcpExt: 12 34\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		parseProcNetCounters(data, "TcpExt:", "SyncookiesSent", "ListenDrops")
	})
}

func TestSavedSynListenerWatchCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ln := new(savedSynListener)
	ln.watchSYNRate(ctx)
}
