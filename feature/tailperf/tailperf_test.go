// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tailperf

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	core "tailscale.com/tailperf"
)

func TestTailperfCapRules(t *testing.T) {
	caps := tailcfg.PeerCapMap{
		tailcfg.PeerCapability("tailscale.io/cap/tailperf"): []tailcfg.RawMessage{
			`{"tun_listen_port":22345}`,
		},
		tailcfg.PeerCapability("https://tailscale.com/cap/tailperf"): []tailcfg.RawMessage{
			`{"userspace_listen_port":12345}`,
		},
	}
	rules, err := tailperfCapRules(caps)
	if err != nil {
		t.Fatalf("tailperfCapRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	if rules[0].TUNListenPort != 22345 {
		t.Fatalf("rules[0].TUNListenPort = %d, want 22345", rules[0].TUNListenPort)
	}
	if rules[1].UserspaceListenPort != 12345 {
		t.Fatalf("rules[1].UserspaceListenPort = %d, want 12345", rules[1].UserspaceListenPort)
	}
}

func TestAllowedPort(t *testing.T) {
	rules := []tailcfg.TailperfCapRule{{
		UserspaceListenPort: 12345,
		TUNListenPort:       22345,
	}}
	if got, ok := allowedPort(rules, false, 0); !ok || got != 22345 {
		t.Fatalf("TUN allowedPort = %d, %v; want 22345, true", got, ok)
	}
	if got, ok := allowedPort(rules, true, 12345); !ok || got != 12345 {
		t.Fatalf("userspace allowedPort = %d, %v; want 12345, true", got, ok)
	}
	if _, ok := allowedPort(rules, false, 12345); ok {
		t.Fatal("requested userspace port accepted for TUN mode")
	}
	if _, ok := allowedPort([]tailcfg.TailperfCapRule{{}}, false, 0); ok {
		t.Fatal("empty port config accepted")
	}
}

func TestManagerStartRejectsConcurrent(t *testing.T) {
	var m manager
	port := freeTCPPort(t)
	if _, err := m.Start(context.Background(), core.ServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		Protocol: core.ProtoTCP,
	}, time.Second); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := m.Start(context.Background(), core.ServerConfig{
		Addr:     "127.0.0.1",
		Port:     freeTCPPort(t),
		Protocol: core.ProtoTCP,
	}, time.Second); !errors.Is(err, errBusy) {
		t.Fatalf("second Start error = %v, want errBusy", err)
	}
	m.mu.Lock()
	cancel := m.cancel
	m.mu.Unlock()
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		done := m.cancel == nil
		m.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("manager did not clean up after cancellation")
}

func TestManagerStartReportsListenFailure(t *testing.T) {
	var m manager
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	if _, err := m.Start(context.Background(), core.ServerConfig{
		Addr:     "127.0.0.1",
		Port:     port,
		Protocol: core.ProtoTCP,
	}, time.Second); err == nil {
		t.Fatal("Start succeeded on an already-bound port")
	}
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}
