// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/feature/loginbeacon/api"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnlocal/ipnlocaltest"
	"tailscale.com/ipn/localapi"
	"tailscale.com/tsd"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
)

// These tests use direct handlers and unicast loopback sockets, never multicast.
func testSender(t *testing.T) *Sender {
	t.Helper()
	s := &Sender{cfg: Config{Logf: t.Logf}}
	if _, err := s.getOrStartSession("https://login.tailscale.com/a/test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.sessKey.zero() })
	return s
}

func testReceiver(t *testing.T) *Receiver {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	return &Receiver{
		cfg: ReceiverConfig{Logf: t.Logf, OnBeacon: func(Beacon) {}, URLAllowed: api.DefaultURLAllowed},
		ctx: ctx, cancel: cancel,
		pending: make(map[requestID]*pendingBeacon), deleted: make(map[requestID]time.Time),
	}
}

func testSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func testAdvertise(t *testing.T, r *Receiver, m *beaconMsg, src *net.UDPAddr) {
	t.Helper()
	packet, err := marshalBeacon(m)
	if err != nil {
		t.Fatal(err)
	}
	r.handleBeacon(packet, src)
}

func TestInvalidApprovalDoesNotConsumeSession(t *testing.T) {
	s := testSender(t)
	bad := &approvalMsg{RequestID: s.sessRID} // invalid all-zero X25519 key
	if _, err := s.approvalResponse(bad); err == nil {
		t.Fatal("invalid key accepted")
	}
	if s.sealedReply != nil {
		t.Fatal("invalid approval consumed request")
	}
	approver, err := newEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	defer approver.zero()
	response, err := s.approvalResponse(&approvalMsg{RequestID: s.sessRID, ApproverEphPub: approver.pub})
	if err != nil || response == nil {
		t.Fatalf("valid approval after invalid one: %v", err)
	}
}

func TestApprovalRetransmissionIsBoundToSelectedKey(t *testing.T) {
	s := testSender(t)
	selected, err := newEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	defer selected.zero()
	other, err := newEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	defer other.zero()
	approval := &approvalMsg{RequestID: s.sessRID, ApproverEphPub: selected.pub}
	first, err := s.approvalResponse(approval)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := s.approvalResponse(approval)
	if err != nil || !bytes.Equal(first, retry) {
		t.Fatalf("retry changed response: %v", err)
	}
	rejected, err := s.approvalResponse(&approvalMsg{RequestID: s.sessRID, ApproverEphPub: other.pub})
	if err != nil || rejected != nil {
		t.Fatalf("released URL to another approver: %v", err)
	}
	if _, err := s.getOrStartSession("https://login.tailscale.com/a/new"); err != nil {
		t.Fatal(err)
	}
	response, err := s.approvalResponse(&approvalMsg{RequestID: s.sessRID, ApproverEphPub: other.pub})
	if err != nil || response == nil {
		t.Fatalf("new session retained old approval: %v", err)
	}
}

func TestExpiredSenderSessionDoesNotReleaseURL(t *testing.T) {
	s := testSender(t)
	s.sessExpires = time.Now().Add(-time.Second)
	response, err := s.approvalResponse(&approvalMsg{RequestID: s.sessRID})
	if err != nil || response != nil {
		t.Fatalf("expired session answered: %v", err)
	}
	beacon, err := s.getOrStartSession(s.sessURL)
	if err != nil || beacon != nil {
		t.Fatalf("expired URL restarted its session: %v", err)
	}
}

func TestRequestPinsKeySourceAndDisplayIdentity(t *testing.T) {
	r := testReceiver(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	m := beaconMsg{RequestID: requestID{1}, SenderEphPub: [32]byte{1}, UnixSec: time.Now().Unix(), Hostname: "original"}
	var observed []Beacon
	r.cfg.OnBeacon = func(b Beacon) { observed = append(observed, b) }
	testAdvertise(t, r, &m, src)
	changed := m
	changed.SenderEphPub = [32]byte{2}
	testAdvertise(t, r, &changed, src)
	testAdvertise(t, r, &m, &net.UDPAddr{IP: src.IP, Port: src.Port + 1})
	changed = m
	changed.Hostname = "replacement"
	testAdvertise(t, r, &changed, src)
	if len(observed) != 2 || observed[1].Hostname != "original" {
		t.Fatalf("unexpected observations: %+v", observed)
	}
	if r.pending[m.RequestID].beacon.SenderEphPub != m.SenderEphPub {
		t.Fatal("requester key replaced")
	}
}

func TestRequestStateIsBoundedAndExpiresFromFirstReceipt(t *testing.T) {
	r := testReceiver(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	m := beaconMsg{UnixSec: time.Now().Unix()}
	for i := 0; i < api.MaxTrackedRequests+1; i++ {
		m.RequestID = requestID{byte(i), byte(i >> 8)}
		testAdvertise(t, r, &m, src)
	}
	if len(r.pending) != api.MaxTrackedRequests {
		t.Fatalf("pending = %d", len(r.pending))
	}
	id := requestID{}
	firstSeen := r.pending[id].firstSeen
	r.Delete([16]byte(id))
	if len(r.pending)+len(r.deleted) != api.MaxTrackedRequests {
		t.Fatal("Delete lost the state bound")
	}
	if got := r.deleted[id]; !got.Equal(firstSeen.Add(api.RequestRetention)) {
		t.Fatalf("Delete extended retention: %v", got)
	}
	r.mu.Lock()
	r.pruneExpiredLocked(time.Now().Add(api.RequestRetention + time.Second))
	r.mu.Unlock()
	if len(r.pending)+len(r.deleted) != 0 {
		t.Fatal("expired state retained")
	}
}

func TestApproveRetriesLostReplyAndCachesUntilDelete(t *testing.T) {
	s, r := testSender(t), testReceiver(t)
	s.conn = testSocket(t)
	testAdvertise(t, r, &beaconMsg{RequestID: s.sessRID, SenderEphPub: s.sessKey.pub, UnixSec: time.Now().Unix()}, s.conn.LocalAddr().(*net.UDPAddr))
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, maxWireSize)
		var firstKey [32]byte
		for attempt := 0; attempt < 2; attempt++ {
			n, src, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				served <- err
				return
			}
			approval, err := parseApproval(buf[:n])
			if err != nil {
				served <- err
				return
			}
			if attempt == 0 {
				firstKey = approval.ApproverEphPub
			} else if firstKey != approval.ApproverEphPub {
				served <- errors.New("retry changed approver key")
				return
			}
			response, err := s.approvalResponse(approval)
			if err != nil {
				served <- err
				return
			}
			if attempt == 0 {
				continue
			} // deliberately lose the first sealed reply
			_, err = s.conn.WriteToUDP(response, src)
			served <- err
		}
	}()
	url, err := r.Approve(t.Context(), [16]byte(s.sessRID))
	if err != nil || url != s.sessURL {
		t.Fatalf("Approve = %q, %v", url, err)
	}
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if r.pending[s.sessRID] == nil {
		t.Fatal("retrieval removed request before browser handoff")
	}
	again, err := r.Approve(t.Context(), [16]byte(s.sessRID))
	if err != nil || again != url {
		t.Fatalf("browser retry = %q, %v", again, err)
	}
	r.Delete([16]byte(s.sessRID))
	if _, err := r.Approve(t.Context(), [16]byte(s.sessRID)); !errors.Is(err, errNoPendingBeacon) {
		t.Fatalf("deleted request approved: %v", err)
	}
}

func TestDeleteAndShutdownCancelRetrieval(t *testing.T) {
	for _, operation := range []string{"delete", "shutdown", "request-cancel", "sender-cancel"} {
		t.Run(operation, func(t *testing.T) {
			s, r := testSender(t), testReceiver(t)
			s.conn = testSocket(t)
			r.conn = testSocket(t) // lets Stop exercise its real socket cleanup
			testAdvertise(t, r, &beaconMsg{RequestID: s.sessRID, SenderEphPub: s.sessKey.pub, UnixSec: time.Now().Unix()}, s.conn.LocalAddr().(*net.UDPAddr))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := r.Approve(ctx, [16]byte(s.sessRID)); result <- err }()
			// Observing the approval gives a deterministic cancellation boundary.
			if _, _, err := s.conn.ReadFromUDP(make([]byte, maxWireSize)); err != nil {
				t.Fatal(err)
			}
			switch operation {
			case "delete":
				r.Delete([16]byte(s.sessRID))
			case "shutdown":
				r.Stop()
			case "request-cancel":
				cancel()
			case "sender-cancel":
				r.handleBeacon(marshalCancel(s.cancelToken), s.conn.LocalAddr().(*net.UDPAddr))
			}
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("result = %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("retrieval did not cancel")
			}
		})
	}
}

func TestApproveRetainsKeyAcrossCancelledRetrieval(t *testing.T) {
	s, r := testSender(t), testReceiver(t)
	s.conn = testSocket(t)
	testAdvertise(t, r, &beaconMsg{RequestID: s.sessRID, SenderEphPub: s.sessKey.pub, UnixSec: time.Now().Unix()}, s.conn.LocalAddr().(*net.UDPAddr))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := r.Approve(ctx, [16]byte(s.sessRID)); first <- err }()
	buf := make([]byte, maxWireSize)
	n, _, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := parseApproval(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	// Select the first key, but cancel retrieval before delivering its reply.
	if _, err := s.approvalResponse(initial); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled retrieval = %v", err)
	}
	replied := make(chan error, 1)
	go func() {
		n, src, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			replied <- err
			return
		}
		retry, err := parseApproval(buf[:n])
		if err != nil {
			replied <- err
			return
		}
		if retry.ApproverEphPub != initial.ApproverEphPub {
			replied <- errors.New("retry changed selected key")
			return
		}
		response, err := s.approvalResponse(retry)
		if err != nil {
			replied <- err
			return
		}
		_, err = s.conn.WriteToUDP(response, src)
		replied <- err
	}()
	url, err := r.Approve(t.Context(), [16]byte(s.sessRID))
	if err != nil || url != s.sessURL {
		t.Fatalf("retry = %q, %v", url, err)
	}
	if err := <-replied; err != nil {
		t.Fatal(err)
	}
}

func TestShutdownCannotReturnCachedURL(t *testing.T) {
	r := testReceiver(t)
	id := requestID{1}
	r.pending[id] = &pendingBeacon{firstSeen: time.Now(), authURL: "https://login.tailscale.com/a/test"}
	r.cancel()
	url, err := r.Approve(t.Context(), [16]byte(id))
	if !errors.Is(err, context.Canceled) || url != "" {
		t.Fatalf("shutdown returned %q, %v", url, err)
	}
}

func TestWireParsersRejectWrongMessageTypeAndOversize(t *testing.T) {
	packet := make([]byte, headerSize+32+8+1+1+16)
	writeHeader(packet, msgTypeApproval, requestID{})
	if _, err := parseBeacon(packet); !errors.Is(err, errBadType) {
		t.Fatalf("beacon accepted approval: %v", err)
	}
	writeHeader(packet, msgTypeBeacon, requestID{})
	if _, err := parseApproval(packet); !errors.Is(err, errBadType) {
		t.Fatalf("approval accepted beacon: %v", err)
	}
	if _, err := parseSealedURL(packet); !errors.Is(err, errBadType) {
		t.Fatalf("sealed URL accepted beacon: %v", err)
	}
	oversized := make([]byte, maxWireSize+1)
	writeHeader(oversized, msgTypeBeacon, requestID{})
	if _, _, err := parseHeader(oversized); !errors.Is(err, errBadLength) {
		t.Fatalf("oversized header accepted: %v", err)
	}
}

// Explicit broadcast tests use stub senders with loopback sockets. Nothing is
// multicast onto the test host's LAN.
func TestTVBroadcastRequiresExplicitStartAndRestartsSameURL(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	e := &extension{ctx: ctx, cancel: cancel, logf: t.Logf, deviceID: "test-tv-instance"}
	e.newSender = func(ctx context.Context, cfg Config) (*Sender, error) {
		ctx, cancel := context.WithCancel(ctx)
		return &Sender{ctx: ctx, cancel: cancel, cfg: cfg, conn: testSocket(t)}, nil
	}
	t.Cleanup(func() { e.Shutdown() })
	url := "https://login.tailscale.com/a/test"
	e.onNotify(&ipn.Notify{BrowseToURL: &url})
	if e.currentAuthURL() != "" || e.sender != nil {
		t.Fatal("prefetch must not advertise before the button is pressed")
	}
	if err := e.testBroadcast(true, "Living Room’s Apple TV"); err != nil {
		t.Fatal(err)
	}
	first := e.sender
	beacon, err := first.getOrStartSession(first.cfg.AuthURL())
	if err != nil {
		t.Fatal(err)
	}
	if beacon.Hostname != "Living Room’s Apple TV" || first.cfg.Hostname != "Living Room’s Apple TV" {
		t.Fatalf("broadcast hostname = %q; want native device name", beacon.Hostname)
	}
	firstID := beacon.RequestID

	// Re-click without a stop: a receiver may have expired/suppressed firstID.
	if err := e.testBroadcast(true, "Den Apple TV"); err != nil {
		t.Fatal(err)
	}
	second := e.sender
	if second.cfg.DeviceID != first.cfg.DeviceID || second.cfg.DeviceID == second.cfg.Hostname {
		t.Fatal("retry/rename must retain the sender instance ID independently of the display name")
	}
	if second.cfg.Hostname != "Den Apple TV" {
		t.Fatalf("restarted broadcast hostname = %q; want updated device name", second.cfg.Hostname)
	}
	beacon, err = second.getOrStartSession(second.cfg.AuthURL())
	if err != nil {
		t.Fatal(err)
	}
	if second == first || beacon.RequestID == firstID {
		t.Fatal("a new button press must create a fresh request for the same URL")
	}
	if first.sessURL != "" || first.ctx.Err() == nil {
		t.Fatal("previous broadcast must stop and clear its URL")
	}
	if err := e.testBroadcast(false, ""); err != nil {
		t.Fatal(err)
	}
	if e.sender != nil || e.currentAuthURL() != "" || second.ctx.Err() == nil {
		t.Fatal("cancel must stop advertising")
	}
	if err := e.testBroadcast(true, "Living Room’s Apple TV"); err != nil {
		t.Fatal(err)
	}
	e.onBackendStateChange(ipn.Running)
	e.onNotify(&ipn.Notify{BrowseToURL: &url})
	if e.currentAuthURL() != "" {
		t.Fatal("a later prefetch must not re-arm broadcasting after sign-in")
	}
	e.Shutdown()
	if err := e.testBroadcast(true, "Living Room’s Apple TV"); !errors.Is(err, context.Canceled) {
		t.Fatalf("start after shutdown = %v", err)
	}
}

func TestTVBroadcastReportsMissingURLAndSenderFailure(t *testing.T) {
	e := &extension{ctx: t.Context(), logf: t.Logf, deviceID: "test-tv-instance"}
	if err := e.testBroadcast(true, "Living Room’s Apple TV"); err == nil {
		t.Fatal("start without an auth URL succeeded")
	}
	e.url = "https://login.tailscale.com/a/test"
	wantErr := errors.New("no LAN interface")
	e.newSender = func(context.Context, Config) (*Sender, error) { return nil, wantErr }
	if err := e.testBroadcast(true, "Living Room’s Apple TV"); !errors.Is(err, wantErr) {
		t.Fatalf("start = %v", err)
	}
	if e.broadcastEnabled || e.sender != nil {
		t.Fatal("failed start left broadcasting enabled")
	}
}

func TestNewRequestSupersedesSameInstanceAndSource(t *testing.T) {
	r := testReceiver(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	old := beaconMsg{RequestID: requestID{1}, SenderEphPub: [32]byte{1}, UnixSec: time.Now().Unix(), Hostname: "TV", DeviceIDHash: hashDeviceID("instance")}
	var observed []Beacon
	r.cfg.OnBeacon = func(b Beacon) { observed = append(observed, b) }
	testAdvertise(t, r, &old, src)
	previous := r.pending[old.RequestID]
	key, err := newEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	previous.key = &key
	previous.authURL = "https://login.tailscale.com/a/test"
	cancelled := make(chan struct{})
	previous.cancel = func() { close(cancelled) }
	next := old
	next.RequestID = requestID{2}
	next.SenderEphPub = [32]byte{2}
	next.Hostname = "Renamed TV"
	testAdvertise(t, r, &next, &net.UDPAddr{IP: src.IP, Port: src.Port + 1})
	if len(r.pending) != 1 || r.pending[next.RequestID] == nil {
		t.Fatal("retry did not replace the pending request")
	}
	if _, exists := r.deleted[old.RequestID]; !exists {
		t.Fatal("superseded request not tombstoned")
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("superseded retrieval not cancelled")
	}
	if key.priv != ([32]byte{}) || previous.authURL != "" {
		t.Fatal("superseded request retained secrets")
	}
	if len(observed) != 2 || observed[0].RequesterID == "" || observed[0].RequesterID != observed[1].RequesterID {
		t.Fatalf("retry changed source-scoped instance identity: %+v", observed)
	}
	testAdvertise(t, r, &old, src)
	if len(observed) != 2 || len(r.pending) != 1 {
		t.Fatal("delayed old beacon resurrected a superseded request")
	}
	if _, err := r.Approve(t.Context(), [16]byte(old.RequestID)); !errors.Is(err, errNoPendingBeacon) {
		t.Fatalf("superseded request can still approve: %v", err)
	}
}

func TestDifferentInstancesAndSourcesDoNotSupersede(t *testing.T) {
	r := testReceiver(t)
	var identities []string
	r.cfg.OnBeacon = func(b Beacon) { identities = append(identities, b.RequesterID) }
	first := beaconMsg{RequestID: requestID{1}, SenderEphPub: [32]byte{1}, UnixSec: time.Now().Unix(), Hostname: "TV", DeviceIDHash: hashDeviceID("one")}
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	testAdvertise(t, r, &first, src)
	second := first
	second.RequestID = requestID{2}
	second.DeviceIDHash = hashDeviceID("two")
	testAdvertise(t, r, &second, src)
	third := first
	third.RequestID = requestID{3} // copied device ID, different LAN source
	testAdvertise(t, r, &third, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 12345})
	if len(r.pending) != 3 || len(r.deleted) != 0 {
		t.Fatal("unrelated request was superseded")
	}
	if len(identities) != 3 || identities[0] == identities[1] || identities[0] == identities[2] || identities[1] == identities[2] {
		t.Fatalf("unrelated senders share a client identity: %v", identities)
	}
}

func TestExplicitBroadcastWorksForHeadlessAppliancesAndLinux(t *testing.T) {
	for _, cfg := range []*senderCfg{nil, {hostname: "Headless Appliance", kind: "appliance"}} {
		e := &extension{ctx: t.Context(), logf: t.Logf, deviceID: "test-headless-instance", senderConfig: cfg}
		e.url = "https://login.tailscale.com/a/test"
		e.newSender = func(ctx context.Context, c Config) (*Sender, error) {
			ctx, cancel := context.WithCancel(ctx)
			return &Sender{ctx: ctx, cancel: cancel, cfg: c, conn: testSocket(t)}, nil
		}
		if err := e.testBroadcast(true, ""); err != nil {
			t.Fatal(err)
		}
		if e.sender.cfg.DeviceKind == "tvos" {
			t.Fatal("headless broadcast forced the TV device kind")
		}
		if cfg != nil && (e.sender.cfg.DeviceKind != cfg.kind || e.sender.cfg.Hostname != cfg.hostname) {
			t.Fatal("appliance configuration not preserved")
		}
		if err := e.testBroadcast(false, ""); err != nil {
			t.Fatal(err)
		}
		if e.sender != nil {
			t.Fatal("headless cancel left sender running")
		}
	}
}

func TestReceiverDoesNotSurfaceItsOwnBroadcast(t *testing.T) {
	r := testReceiver(t)
	r.cfg.IgnoreDeviceIDHash = hashDeviceID("local-instance")
	m := beaconMsg{RequestID: requestID{1}, UnixSec: time.Now().Unix(), DeviceIDHash: r.cfg.IgnoreDeviceIDHash}
	r.cfg.OnBeacon = func(Beacon) { t.Fatal("receiver surfaced its own daemon's broadcast") }
	testAdvertise(t, r, &m, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345})
	if len(r.pending) != 0 {
		t.Fatal("receiver retained its own broadcast")
	}
}

func TestSenderHandlingWindow(t *testing.T) {
	for _, sendErr := range []error{nil, errors.New("send failed")} {
		name := "success"
		if sendErr != nil {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := testSender(t)
				selected, _ := newEphemeralKey()
				defer selected.zero()
				other, _ := newEphemeralKey()
				defer other.zero()
				approval := &approvalMsg{RequestID: s.sessRID, ApproverEphPub: selected.pub}
				response, err := s.approvalResponse(approval)
				if err != nil || response == nil {
					t.Fatalf("select: %v", err)
				}
				// Recipient selection pauses broadcasts before the socket write.
				if m, _ := s.getOrStartSession(s.sessURL); m != nil {
					t.Fatal("broadcast while sending URL")
				}
				if reply, _ := s.approvalResponse(&approvalMsg{RequestID: s.sessRID, ApproverEphPub: other.pub}); reply != nil {
					t.Fatal("second recipient selected")
				}
				s.mu.Lock()
				s.finishSendLocked(time.Now(), sendErr)
				s.mu.Unlock()
				if sendErr == nil {
					deadline := s.resumeAt
					time.Sleep(5 * time.Second)
					if m, _ := s.getOrStartSession(s.sessURL); m != nil {
						t.Fatal("broadcast during handling window")
					}
					if reply, _ := s.approvalResponse(approval); reply == nil {
						t.Fatal("same-recipient retry rejected")
					}
					s.mu.Lock()
					s.finishSendLocked(time.Now(), nil)
					s.mu.Unlock()
					if s.resumeAt != deadline {
						t.Fatal("retry extended handling window")
					}
					// A failed retransmission must not release a previously successful claim.
					s.mu.Lock()
					s.finishSendLocked(time.Now(), errors.New("retry failed"))
					s.mu.Unlock()
					if s.resumeAt != deadline {
						t.Fatal("retry error released claim")
					}
					time.Sleep(time.Until(deadline))
				}
				// Even after failure/deadline, approvals remain closed until a tick.
				if reply, _ := s.approvalResponse(approval); reply != nil {
					t.Fatal("approval reopened before broadcast tick")
				}
				if m, _ := s.getOrStartSession(s.sessURL); m == nil {
					t.Fatal("next tick did not resume discovery")
				}
				if reply, _ := s.approvalResponse(&approvalMsg{RequestID: s.sessRID, ApproverEphPub: other.pub}); reply == nil {
					t.Fatal("new recipient rejected after resumed broadcast")
				}
			})
		})
	}
}

func testExtension(t *testing.T) *extension {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	e := &extension{ctx: ctx, cancel: cancel, logf: t.Logf, deviceID: "test", url: "https://login.tailscale.com/a/test"}
	e.newSender = func(ctx context.Context, c Config) (*Sender, error) {
		ctx, cancel := context.WithCancel(ctx)
		return &Sender{ctx: ctx, cancel: cancel, cfg: c, conn: testSocket(t)}, nil
	}
	t.Cleanup(func() { e.Shutdown() })
	return e
}

func TestBroadcastIdempotenceReplacementAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := testExtension(t)
		e.receiverDone, e.receiverControl = make(chan struct{}), make(chan struct{}, 1)
		go e.runReceiver(nil)
		config := api.Broadcast{Expires: time.Now().Add(time.Minute)}
		a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
		if err := e.changeBroadcast(a, "alice", config, true); err != nil {
			t.Fatal(err)
		}
		original := senderOf(e)
		if err := e.changeBroadcast(a, "alice", config, true); err != nil || senderOf(e) != original {
			t.Fatal("PUT restarted attempt")
		}
		if err := e.changeBroadcast(a, "bob", config, false); err == nil || senderOf(e) != original {
			t.Fatal("another owner stopped attempt")
		}
		changed := config
		changed.Expires = changed.Expires.Add(time.Minute)
		if err := e.changeBroadcast(a, "alice", changed, true); err == nil {
			t.Fatal("PUT extended existing attempt")
		}
		if err := e.changeBroadcast(b, "alice", changed, true); err != nil {
			t.Fatal(err)
		}
		replacement := senderOf(e)
		if err := e.changeBroadcast(strings.Repeat("c", 32), "bob", changed, true); err == nil || senderOf(e) != replacement {
			t.Fatal("another user replaced the attempt")
		}
		if original.ctx.Err() == nil {
			t.Fatal("old sender still active")
		}
		if err := e.changeBroadcast(a, "alice", config, false); err != nil || senderOf(e) != replacement {
			t.Fatal("stale stop affected replacement")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if senderOf(e) != replacement {
			t.Fatal("old expiry affected replacement")
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if senderOf(e) != nil || replacement.ctx.Err() == nil {
			t.Fatal("daemon expiry did not stop attempt")
		}
	})
}

func senderOf(e *extension) *Sender {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sender
}

func TestRequestSnapshotExcludesSecretsAndHandledRequests(t *testing.T) {
	r := testReceiver(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	for i := byte(1); i <= 3; i++ {
		testAdvertise(t, r, &beaconMsg{RequestID: requestID{i}, Hostname: "device", UnixSec: time.Now().Unix()}, src)
	}
	r.pending[requestID{1}].authURL = "secret" // retrieval does not complete handoff
	r.Delete([16]byte{2})
	r.pending[requestID{3}].firstSeen = time.Now().Add(-api.RequestRetention)
	got := r.requests()
	if len(got) != 1 || got[0].RequestID != "01000000000000000000000000000000" {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestResourceRoutes(t *testing.T) {
	sys := tsd.NewSystem()
	sys.PolicyClient.Set(policytest.Config{pkey.AllowLoginBeacon: false}) // avoid opening multicast sockets
	b := ipnlocaltest.NewBackendWithSys(t, sys)
	b.ForTest().InitExtensions()
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		t.Fatal("missing extension")
	}
	h := localapi.NewHandler(localapi.HandlerConfig{Backend: b, Logf: t.Logf})
	for _, tt := range []struct {
		method, path, body string
		read, write        bool
		want               int
	}{
		{"GET", "/", "", true, false, 200},
		{"GET", "/requests", "", true, false, 200},
		{"GET", "/requests", "", false, false, 403},
		{"POST", "/requests", "", true, false, 403},
		{"POST", "/requests", "", false, true, 405},
		{"DELETE", "/requests/not-hex", "", false, true, 400},
		{"GET", "/requests/" + strings.Repeat("a", 32) + "/approval", "", true, false, 405},
		{"PUT", "/broadcasts/not-hex", "{}", false, true, 400},
		{"PUT", "/broadcasts/", "{}", false, true, 400},
		{"DELETE", "/broadcasts/", "", false, true, 400},
		{"PUT", "/broadcasts/" + strings.Repeat("a", 32), "{}", false, true, 400},
		{"DELETE", "/broadcasts/" + strings.Repeat("a", 32), "", false, true, 204},
		{"PUT", "/receiver", "", false, true, 204},
		{"DELETE", "/receiver", "", false, true, 204},
		{"POST", "/receiver", "", false, true, 405},
		{"GET", "/receiver", "", true, false, 405},
		{"PUT", "/receiver", "", true, false, 403},
		{"DELETE", "/receiver", "", true, false, 403},
		{"POST", "/requests/" + strings.Repeat("a", 32) + "/approval", "", true, false, 403},
		{"DELETE", "/requests/" + strings.Repeat("a", 32), "", true, false, 403},
		{"PUT", "/broadcasts/" + strings.Repeat("a", 32), "{}", true, false, 403},
		{"DELETE", "/broadcasts/" + strings.Repeat("a", 32), "", true, false, 403},
		{"POST", "-start", "", false, true, 404},
		{"POST", "-stop", "", false, true, 404},
		{"POST", "-receiver?active=true", "", false, true, 404},
		{"POST", "-approve", "", false, true, 404},
		{"POST", "-delete", "", false, true, 404},
		{"POST", "-ignore", "", false, true, 404},
	} {
		t.Run(tt.method+"/"+tt.path, func(t *testing.T) {
			h.PermitRead, h.PermitWrite = tt.read, tt.write
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(tt.method, "http://"+apitype.LocalAPIHost+"/localapi/v0/loginbeacon"+tt.path, strings.NewReader(tt.body)))
			if w.Code != tt.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if tt.path == "/receiver" && tt.want == 204 {
				e.mu.Lock()
				active := time.Now().Before(e.receiverLeaseUntil)
				e.mu.Unlock()
				if active != (tt.method == http.MethodPut) {
					t.Fatal("foreground reception lease was not updated")
				}
			}
		})
	}
	if !e.status().AcceptRequests {
		t.Fatal("reception preference was not enabled by default")
	}
}

func TestSenderStartupCannotUndoRevocation(t *testing.T) {
	for _, revoke := range []string{"profile", "policy"} {
		t.Run(revoke, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := testExtension(t)
				create := e.newSender
				started, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
				var created *Sender
				e.newSender = func(ctx context.Context, config Config) (*Sender, error) {
					close(started)
					<-release
					var err error
					created, err = create(ctx, config)
					return created, err
				}
				go func() { finished <- e.testBroadcast(true, "") }()
				<-started
				if revoke == "profile" {
					e.onProfileStateChange(ipn.LoginProfileView{}, (&ipn.Prefs{}).View(), false)
				} else {
					e.polc = policytest.Config{pkey.AllowLoginBeacon: false}
					e.updatePolicy()
				}
				close(release)
				if err := <-finished; err == nil {
					t.Fatal("revoked broadcast start succeeded")
				}
				if e.sender != nil || created.ctx.Err() == nil {
					t.Fatal("revoked sender was published instead of stopped")
				}
			})
		})
	}
}

func TestAutomaticSenderPolicyAndExplicitStop(t *testing.T) {
	e := testExtension(t)
	e.automaticSender = true
	e.senderConfig = &senderCfg{kind: "appliance"}
	e.polc = policytest.Config{pkey.AllowLoginBeacon: false}
	e.updatePolicy()
	e.cleanupSender()
	if e.sender != nil || !e.automaticSender {
		t.Fatal("policy denial started sender or lost provisioning opt-in")
	}
	e.polc = policytest.Config{}
	e.updatePolicy()
	e.cleanupSender()
	id := e.status().BroadcastID
	if e.sender == nil || id == "" {
		t.Fatal("policy reallow did not restore provisioned sender with a stoppable ID")
	}
	if err := e.changeBroadcast(id, "", api.Broadcast{}, false); err != nil {
		t.Fatal(err)
	}
	e.cleanupSender() // A later network/backend wake must not re-arm the sender.
	if e.sender != nil || e.automaticSender || e.currentAuthURL() != "" {
		t.Fatal("explicit stop did not override appliance automation")
	}
}

func (e *extension) testBroadcast(enabled bool, hostname string) error {
	id := e.status().BroadcastID
	config := api.Broadcast{Hostname: hostname}
	if enabled {
		var rid [16]byte
		rand.Read(rid[:])
		id = hex.EncodeToString(rid[:])
		config.Expires = time.Now().Add(api.MaxBroadcastDuration)
	} else if id == "" {
		return nil
	}
	return e.changeBroadcast(id, "", config, enabled)
}
