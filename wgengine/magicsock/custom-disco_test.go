// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_customdisco

package magicsock

import (
	"errors"
	"testing"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/netaddr"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const testCustomDiscoType = disco.MessageType(0x80)

// testCustomDiscoMsg is a minimal custom disco message for testing.
type testCustomDiscoMsg struct {
	Data [4]byte
}

func (m *testCustomDiscoMsg) AppendMarshal(b []byte) []byte {
	b = append(b, byte(testCustomDiscoType), 0) // type, version
	b = append(b, m.Data[:]...)
	return b
}

func TestCustomDiscoMessage(t *testing.T) {
	ln, ip := localhostListener{}, netaddr.IPv4(127, 0, 0, 1)
	d := &devices{
		m1:     ln,
		m1IP:   ip,
		m2:     ln,
		m2IP:   ip,
		stun:   ln,
		stunIP: ip,
	}

	logf, closeLogf := logger.LogfCloser(t.Logf)
	defer closeLogf()

	derpMap, cleanup := runDERPAndStun(t, logf, d.stun, d.stunIP)
	defer cleanup()

	m1 := newMagicStack(t, logger.WithPrefix(logf, "m1: "), d.m1, derpMap)
	defer m1.Close()
	m2 := newMagicStack(t, logger.WithPrefix(logf, "m2: "), d.m2, derpMap)
	defer m2.Close()

	cleanupMesh := meshStacks(logf, nil, m1, m2)
	defer cleanupMesh()

	// Channel to receive the custom disco message on m2.
	gotMsg := make(chan *testCustomDiscoMsg, 1)

	parseHook := func(msgType disco.MessageType, ver uint8, p []byte) (disco.Message, error) {
		if msgType != testCustomDiscoType {
			return nil, nil
		}
		if len(p) < 4 {
			return nil, errors.New("short message")
		}
		m := &testCustomDiscoMsg{}
		copy(m.Data[:], p[:4])
		return m, nil
	}

	handleMsg := func(dm disco.Message, sender key.DiscoPublic, derpNodeSrc key.NodePublic) {
		if cm, ok := dm.(*testCustomDiscoMsg); ok {
			gotMsg <- cm
		}
	}

	// Register on both sides so m1 can send and m2 can receive.
	msgDef := &CustomDiscoMessage{
		MessageType:   testCustomDiscoType,
		Parse:         parseHook,
		HandleMessage: handleMsg,
	}
	m1.conn.AddCustomDiscoMessage(msgDef)
	m2.conn.AddCustomDiscoMessage(msgDef)

	// Wait for the mesh to be fully established.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st1 := m1.Status()
		st2 := m2.Status()
		if p := st1.Peer[m2.Public()]; p != nil && p.InMagicSock {
			if p := st2.Peer[m1.Public()]; p != nil && p.InMagicSock {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Send a custom disco message from m1 to m2 over DERP region 1.
	want := [4]byte{'t', 'e', 's', 't'}
	sent, err := m1.conn.SendCustomDiscoOverDERP(
		m2.conn.DiscoPublicKey(),
		m2.privateKey.Public(),
		1, // DERP region
		&testCustomDiscoMsg{Data: want},
	)
	if err != nil {
		t.Fatalf("SendCustomDiscoOverDERP: %v", err)
	}
	if !sent {
		t.Fatal("SendCustomDiscoOverDERP reported not sent")
	}

	select {
	case got := <-gotMsg:
		if got.Data != want {
			t.Errorf("got data %q, want %q", got.Data, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for custom disco message")
	}
}
