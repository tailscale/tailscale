// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios)

package magicsock

import (
	"fmt"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"tailscale.com/net/netaddr"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func TestPeerConnSelfTest(t *testing.T) {
	if err := peerConnSelfTest(); err != nil {
		t.Fatal(err)
	}
}

// TestConnectedSockets brings up two nodes over loopback with connected
// per-peer sockets enabled and checks that, once they find a direct path,
// traffic in both directions moves onto the per-peer sockets, that a rebind
// drops and then re-establishes them, and that shutdown is clean.
func TestConnectedSockets(t *testing.T) {
	tstest.PanicOnLog()
	tstest.ResourceCheck(t)

	if !peerConnSupported(t.Logf) {
		t.Skip("connected per-peer sockets unsupported on this kernel")
	}

	tlogf, setT := makeNestable(t)
	setT(t)
	logf, closeLogf := logger.LogfCloser(tlogf)
	defer closeLogf()

	ln := localhostListener{
		control: func(network, address string, c syscall.RawConn) error {
			return setReusePort(c)
		},
	}
	derpMap, cleanup := runDERPAndStun(t, logf, localhostListener{}, netaddr.IPv4(127, 0, 0, 1))
	defer cleanup()

	enable := func(o *Options) { o.testOnlyConnectedSockets = true }
	m1 := newMagicStackWithKey(t, logger.WithPrefix(logf, "conn1: "), ln, derpMap, key.NewNode(), enable)
	defer m1.Close()
	m2 := newMagicStackWithKey(t, logger.WithPrefix(logf, "conn2: "), ln, derpMap, key.NewNode(), enable)
	defer m2.Close()
	for _, m := range []*magicStack{m1, m2} {
		if !m.conn.peerConns.enabled {
			t.Fatalf("%v: connected sockets not enabled", m)
		}
	}

	cleanup = meshStacks(logf, nil, m1, m2)
	defer cleanup()

	cleanup = newPinger(t, logf, m1, m2)
	defer cleanup()

	mustDirect(t, logf, m1, m2)
	mustDirect(t, logf, m2, m1)

	sendBefore, recvBefore := metricSendPeerConn.Value(), metricRecvPeerConn.Value()
	pc1 := mustPeerConn(t, m1, m2)
	pc2 := mustPeerConn(t, m2, m1)
	if pc1.addr != pc2.localAddrPort() {
		t.Errorf("m1's peerConn is to %v, but m2's local address is %v", pc1.addr, pc2.localAddrPort())
	}
	if pc2.addr != pc1.localAddrPort() {
		t.Errorf("m2's peerConn is to %v, but m1's local address is %v", pc2.addr, pc1.localAddrPort())
	}
	waitFor(t, "traffic over peerConns", func() error {
		sent, recvd := metricSendPeerConn.Value()-sendBefore, metricRecvPeerConn.Value()-recvBefore
		if sent == 0 || recvd == 0 {
			return fmt.Errorf("sent=%d recvd=%d packets via peerConns", sent, recvd)
		}
		return nil
	})

	// A rebind closes the peerConns; ongoing traffic reopens them.
	m1.conn.Rebind()
	if !pc1.closed.Load() {
		t.Error("m1's peerConn survived Rebind")
	}
	waitFor(t, "peerConn reopened after rebind", func() error {
		pc := peerConnOf(m1, m2)
		if pc == nil {
			return fmt.Errorf("no peerConn")
		}
		if pc == pc1 {
			return fmt.Errorf("still the old peerConn")
		}
		return nil
	})
}

// peerConnOf returns from's current peerConn to to, or nil.
func peerConnOf(from, to *magicStack) *peerConn {
	from.conn.mu.Lock()
	defer from.conn.mu.Unlock()
	de, ok := from.conn.peerMap.endpointForNodeKey(to.Public())
	if !ok {
		return nil
	}
	de.mu.Lock()
	defer de.mu.Unlock()
	return de.peerConn
}

func mustPeerConn(t *testing.T, from, to *magicStack) *peerConn {
	t.Helper()
	var pc *peerConn
	waitFor(t, fmt.Sprintf("peerConn %v->%v", from, to), func() error {
		pc = peerConnOf(from, to)
		if pc == nil {
			return fmt.Errorf("no peerConn yet")
		}
		return nil
	})
	return pc
}

func (pc *peerConn) localAddrPort() netip.AddrPort {
	return netaddr.Unmap(pc.pconn.LocalAddr().(interface{ AddrPort() netip.AddrPort }).AddrPort())
}

// waitFor polls f until it returns nil or a deadline passes.
func waitFor(t *testing.T, what string, f func() error) {
	t.Helper()
	var err error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if err = f(); err == nil {
			return
		}
	}
	t.Fatalf("timeout waiting for %s: %v", what, err)
}
