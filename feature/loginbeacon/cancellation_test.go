// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/feature/loginbeacon/api"
)

func TestSenderWithdrawsSession(t *testing.T) {
	for _, operation := range []string{"stop", "url-cleared", "url-replaced", "expired", "parent-canceled"} {
		t.Run(operation, func(t *testing.T) {
			s := testSender(t)
			s.ctx, s.cancel = context.WithCancel(t.Context())
			defer s.cancel()
			s.conn = testSocket(t)
			destination := testSocket(t)
			s.dst = destination.LocalAddr().(*net.UDPAddr)
			rid := s.sessRID
			s.cfg.AuthURL = func() string { return "" }
			switch operation {
			case "stop":
				s.Stop()
			case "url-cleared":
				s.tick()
			case "url-replaced":
				if _, err := s.getOrStartSession("https://login.tailscale.com/a/replacement"); err != nil {
					t.Fatal(err)
				}
			case "expired":
				s.sessExpires = time.Now().Add(-time.Second)
				if _, err := s.getOrStartSession(s.sessURL); err != nil {
					t.Fatal(err)
				}
			case "parent-canceled":
				s.cancel()
				s.wg.Add(2)
				go s.sendLoop()
				go s.recvLoop()
				s.wg.Wait()
			}
			buf := make([]byte, maxWireSize)
			for range 3 {
				n, _, err := destination.ReadFromUDP(buf)
				if err != nil {
					t.Fatal(err)
				}
				if got, err := parseCancel(buf[:n]); err != nil || got != rid {
					t.Fatalf("cancellation = %x, %v; want %x", got, err, rid)
				}
			}
		})
	}
}

func TestCancellationRequiresProofAndPinnedSource(t *testing.T) {
	s, r := testSender(t), testReceiver(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	m := beaconMsg{RequestID: s.sessRID, SenderEphPub: s.sessKey.pub, UnixSec: time.Now().Unix()}
	testAdvertise(t, r, &m, src)
	pb := r.pending[s.sessRID]
	key, err := newEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	pb.key = &key
	pb.authURL = "https://login.tailscale.com/a/test"
	canceled := false
	pb.cancel = func() { canceled = true }
	var removed [][16]byte
	r.cfg.OnRemoved = func(id [16]byte) { removed = append(removed, id) }
	packet := marshalCancel(s.cancelToken)
	forged := append([]byte(nil), packet...)
	forged[len(forged)-1] ^= 1
	r.handleBeacon(forged, src)
	r.handleBeacon(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: src.Port})
	r.handleBeacon(packet, &net.UDPAddr{IP: src.IP, Port: src.Port + 1})
	if r.pending[s.sessRID] == nil || canceled || len(removed) != 0 {
		t.Fatal("unproven cancellation removed a request")
	}
	r.handleBeacon(packet, src)
	r.handleBeacon(packet, src)  // duplicate goodbye must be harmless
	testAdvertise(t, r, &m, src) // delayed discovery must not resurrect it
	if len(r.requests()) != 0 || !canceled || pb.authURL != "" || pb.key != nil || key.priv != ([32]byte{}) {
		t.Fatal("cancellation retained pending state or secrets")
	}
	if len(removed) != 1 || removed[0] != [16]byte(s.sessRID) {
		t.Fatalf("removals = %x", removed)
	}
}

func TestCancellationOverUDP(t *testing.T) {
	r := testReceiver(t)
	r.conn = testSocket(t)
	beacons := make(chan Beacon, 1)
	removed := make(chan [16]byte, 1)
	r.cfg.OnBeacon = func(b Beacon) { beacons <- b }
	r.cfg.OnRemoved = func(id [16]byte) { removed <- id }
	r.wg.Add(1)
	go r.recvLoop(r.conn)
	defer r.Stop()
	s := testSender(t)
	s.ctx, s.cancel = context.WithCancel(t.Context())
	defer s.Stop()
	s.conn = testSocket(t)
	s.dst = r.conn.LocalAddr().(*net.UDPAddr)
	s.cfg.AuthURL = func() string { return s.sessURL }
	s.tick()
	select {
	case <-beacons:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery was not received")
	}
	s.Stop()
	select {
	case id := <-removed:
		if id != [16]byte(s.sessRID) {
			t.Fatalf("removed wrong request: %x", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("withdrawal was not received")
	}
	if len(r.requests()) != 0 {
		t.Fatal("withdrawal left a phantom request")
	}
}

func TestSilentSenderExpiresAndCanReturn(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := testReceiver(t)
		src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
		m := beaconMsg{RequestID: requestID{1}, UnixSec: time.Now().Unix()}
		testAdvertise(t, r, &m, src)
		var removed int
		r.cfg.OnRemoved = func([16]byte) { removed++ }
		time.Sleep(approvalWindow + beaconInterval)
		if len(r.requests()) != 1 {
			t.Fatal("normal handling pause expired the request")
		}
		m.UnixSec = time.Now().Unix()
		testAdvertise(t, r, &m, src)
		time.Sleep(api.RequestLease - time.Second)
		if len(r.requests()) != 1 {
			t.Fatal("repeated beacon did not renew the lease")
		}
		time.Sleep(time.Second)
		if len(r.requests()) != 0 || removed != 1 {
			t.Fatal("silent sender was not removed at lease expiry")
		}
		m.UnixSec = time.Now().Unix()
		testAdvertise(t, r, &m, src)
		if len(r.requests()) != 1 {
			t.Fatal("sender could not return after a temporary network interruption")
		}
	})
}
