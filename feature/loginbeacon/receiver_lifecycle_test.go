// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_loginbeacon

package loginbeacon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policytest"
)

// Membership operations are fake: these tests never join or send multicast.
type testMulticastGroups struct {
	joins, leaves []string
	err           error
}

func (g *testMulticastGroups) JoinGroup(iface *net.Interface, _ net.Addr) error {
	g.joins = append(g.joins, iface.Name)
	return g.err
}

func (g *testMulticastGroups) LeaveGroup(iface *net.Interface, _ net.Addr) error {
	g.leaves = append(g.leaves, iface.Name)
	return nil
}

func testIPv4Interface(t *testing.T) net.Interface {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifs {
		if hasIPv4Address(iface) {
			// Membership calls are fake, so a loopback interface works too.
			iface.Flags = net.FlagUp | net.FlagMulticast
			return iface
		}
	}
	t.Fatal("no IPv4 interface")
	return net.Interface{}
}

func TestReceiverMembershipRefreshPreservesRequests(t *testing.T) {
	r := testReceiver(t)
	groups := &testMulticastGroups{}
	r.pc = groups
	iface := testIPv4Interface(t)
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	m := beaconMsg{RequestID: requestID{1}, UnixSec: time.Now().Unix()}
	testAdvertise(t, r, &m, src)
	m.RequestID = requestID{2}
	testAdvertise(t, r, &m, src)
	r.Delete([16]byte{2})
	pending := r.pending[requestID{1}]
	cancelled := false
	pending.cancel = func() { cancelled = true }
	pending.authURL = "https://login.tailscale.com/a/test"
	// An interface without an IPv4 address must be skipped before JoinGroup.
	unsupported := net.Interface{Index: -1, Name: "no-ipv4", Flags: net.FlagUp | net.FlagMulticast}
	if err := r.rejoinMulticast([]net.Interface{unsupported, iface}); err != nil {
		t.Fatal(err)
	}
	if len(groups.joins) != 1 || groups.joins[0] != iface.Name {
		t.Fatalf("joined unsupported interfaces: %v", groups.joins)
	}
	// Losing the LAN leaves discovery retryable, without retiring requests.
	if err := r.rejoinMulticast(nil); err == nil {
		t.Fatal("missing LAN did not report a retryable failure")
	}
	groups.err = errors.New("permission not ready")
	if err := r.rejoinMulticast([]net.Interface{iface}); err == nil {
		t.Fatal("failed membership did not report a retryable failure")
	}
	groups.err = nil
	if err := r.rejoinMulticast([]net.Interface{iface}); err != nil {
		t.Fatal(err)
	}
	// Refresh even if the returning Wi-Fi interface has the same name/index.
	if err := r.rejoinMulticast([]net.Interface{iface}); err != nil {
		t.Fatal(err)
	}
	if len(groups.leaves) != 2 || len(r.joined) != 1 {
		t.Fatalf("memberships were not refreshed: leaves=%v joined=%v", groups.leaves, r.joined)
	}
	if r.pending[requestID{1}] != pending || pending.authURL == "" || cancelled {
		t.Fatal("membership refresh changed pending approval state")
	}
	if _, ok := r.deleted[requestID{2}]; !ok {
		t.Fatal("membership refresh discarded a deletion tombstone")
	}
}

func TestReceiverLoopRetriesStartupAndStopsRetryingWhenHealthy(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		e := &extension{acceptRequests: true, ctx: ctx, cancel: cancel, logf: t.Logf, receiverDone: make(chan struct{})}
		t.Cleanup(func() { e.Shutdown() })
		var attempts atomic.Int32
		e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
			if attempts.Add(1) < 3 {
				return nil, errors.New("network not ready")
			}
			r := testReceiver(t)
			r.conn = testSocket(t)
			r.pc = &testMulticastGroups{}
			return r, nil
		}
		wake := make(chan struct{}, 1)
		go e.runReceiver(wake)
		synctest.Wait()
		if attempts.Load() != 1 || receiverOf(e) != nil {
			t.Fatalf("initial startup: attempts=%d receiver=%v", attempts.Load(), receiverOf(e))
		}
		time.Sleep(receiverRetryInterval)
		synctest.Wait()
		if attempts.Load() != 2 {
			t.Fatalf("first retry: attempts=%d", attempts.Load())
		}
		time.Sleep(receiverRetryInterval)
		synctest.Wait()
		if attempts.Load() != 3 || receiverOf(e) == nil {
			t.Fatalf("recovery: attempts=%d receiver=%v", attempts.Load(), receiverOf(e))
		}
		groups := receiverOf(e).pc.(*testMulticastGroups)
		time.Sleep(3 * receiverRetryInterval)
		synctest.Wait()
		if attempts.Load() != 3 || len(groups.joins) != 0 {
			t.Fatal("healthy receiver continued polling/restarting")
		}
		e.Shutdown()
		wake <- struct{}{}
		time.Sleep(2 * receiverRetryInterval)
		synctest.Wait()
		if attempts.Load() != 3 || receiverOf(e) != nil {
			t.Fatal("receiver restarted after shutdown")
		}
	})
}

func TestNetworkAndBackendReadinessRetryReceiverImmediately(t *testing.T) {
	for _, tt := range []struct {
		name string
		wake func(*extension)
	}{
		{"network", (*extension).wakeReceiver},
		{"running", func(e *extension) { e.onBackendStateChange(ipn.Running) }},
		{"needs-login", func(e *extension) { e.onBackendStateChange(ipn.NeedsLogin) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				e := &extension{acceptRequests: true, ctx: ctx, cancel: cancel, logf: t.Logf,
					receiverDone: make(chan struct{}), receiverWake: make(chan struct{}, 1), receiverControl: make(chan struct{}, 1)}
				t.Cleanup(func() { e.Shutdown() })
				var attempts atomic.Int32
				e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
					if attempts.Add(1) == 1 {
						return nil, errors.New("network not ready")
					}
					r := testReceiver(t)
					r.conn = testSocket(t)
					r.pc = &testMulticastGroups{}
					return r, nil
				}
				go e.runReceiver(e.receiverWake)
				synctest.Wait()
				started := time.Now()
				tt.wake(e)
				synctest.Wait()
				if attempts.Load() != 2 || receiverOf(e) == nil || !time.Now().Equal(started) {
					t.Fatal("first readiness event did not retry startup immediately")
				}
				// Burst notifications must not create duplicate listeners.
				for range 100 {
					tt.wake(e)
				}
				synctest.Wait()
				if attempts.Load() != 2 || receiverOf(e) == nil || !time.Now().Equal(started) {
					t.Fatal("readiness did not recover immediately with a single startup retry")
				}
			})
		})
	}
}

func TestInitialBackendReadinessDoesNotRejoin(t *testing.T) {
	for _, beforeStartup := range []bool{true, false} {
		t.Run(fmt.Sprintf("before-startup=%v", beforeStartup), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				e := &extension{acceptRequests: true, ctx: ctx, cancel: cancel, logf: t.Logf,
					receiverDone: make(chan struct{}), receiverWake: make(chan struct{}, 1), receiverControl: make(chan struct{}, 1)}
				t.Cleanup(func() { e.Shutdown() })
				groups := &testMulticastGroups{}
				starts := 0
				e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
					starts++
					r := testReceiver(t)
					r.conn = testSocket(t)
					r.pc = groups
					r.joined = []net.Interface{testIPv4Interface(t)}
					return r, nil
				}
				if beforeStartup {
					e.onBackendStateChange(ipn.NeedsLogin)
				}
				go e.runReceiver(e.receiverWake)
				synctest.Wait()
				r := receiverOf(e)
				if !beforeStartup {
					e.onBackendStateChange(ipn.NeedsLogin)
					synctest.Wait()
				}
				if starts != 1 || len(groups.joins) != 0 || len(groups.leaves) != 0 {
					t.Fatal("initial backend readiness refreshed a healthy receiver")
				}
				e.onBackendStateChange(ipn.Stopped)
				e.onBackendStateChange(ipn.NeedsLogin)
				synctest.Wait()
				if starts != 1 || receiverOf(e) != r || len(groups.leaves) != 1 {
					t.Fatal("backend restart did not refresh the existing receiver")
				}
			})
		})
	}
}

func TestReceiverShutdownWaitsForStartupAndClosesNewSocket(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		e := &extension{acceptRequests: true, ctx: ctx, cancel: cancel, logf: t.Logf, receiverDone: make(chan struct{})}
		started, release := make(chan struct{}), make(chan struct{})
		var receiver *Receiver
		var socket *net.UDPConn
		e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
			close(started)
			<-release
			receiver = testReceiver(t)
			receiver.conn = testSocket(t)
			socket = receiver.conn
			return receiver, nil
		}
		go e.runReceiver(make(chan struct{}))
		<-started
		done := make(chan struct{})
		go func() {
			e.Shutdown()
			close(done)
		}()
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("shutdown returned while startup was still running")
		default:
		}
		close(release)
		<-done
		if receiverOf(e) != nil || receiver.ctx.Err() == nil {
			t.Fatal("shutdown left a receiver alive")
		}
		if _, err := socket.WriteToUDP([]byte{0}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("receiver socket not closed: %v", err)
		}
	})
}

// Read through the production lock even when fake time controls the worker.
func receiverOf(e *extension) *Receiver {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.receiver
}

func TestIOSReceiverRequiresForegroundAndRetainsRequestsAcrossPause(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		e := &extension{acceptRequests: true, ctx: ctx, cancel: cancel, logf: t.Logf, receiverNeedsLease: true,
			receiverDone: make(chan struct{}), receiverWake: make(chan struct{}, 1), receiverControl: make(chan struct{}, 1)}
		t.Cleanup(func() { e.Shutdown() })
		var starts atomic.Int32
		resumed := make(chan *net.UDPConn, 1)
		e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
			starts.Add(1)
			r := testReceiver(t)
			r.conn = testSocket(t)
			r.pc = &testMulticastGroups{}
			return r, nil
		}
		e.resumeReceiver = func(r *Receiver) error {
			r.conn = testSocket(t)
			r.pc = &testMulticastGroups{}
			resumed <- r.conn
			return nil
		}
		go e.runReceiver(e.receiverWake)
		synctest.Wait()
		// Backend and network recovery must never override background policy.
		e.onBackendStateChange(ipn.Running)
		e.wakeReceiver()
		time.Sleep(2 * receiverRetryInterval)
		synctest.Wait()
		if starts.Load() != 0 {
			t.Fatal("iOS listened without a foreground lease")
		}
		if err := e.setReceiverActivity(true); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		r := receiverOf(e)
		if r == nil {
			t.Fatal("foregrounding did not start reception")
		}
		socket := r.conn
		src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
		testAdvertise(t, r, &beaconMsg{RequestID: requestID{1}, UnixSec: time.Now().Unix()}, src)
		testAdvertise(t, r, &beaconMsg{RequestID: requestID{2}, UnixSec: time.Now().Unix()}, src)
		r.Delete([16]byte{2})
		pending := r.pending[requestID{1}]
		if err := e.setReceiverActivity(false); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if _, err := socket.WriteToUDP([]byte{0}, src); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("background socket not closed: %v", err)
		}
		e.onBackendStateChange(ipn.NeedsLogin)
		e.wakeReceiver()
		time.Sleep(receiverActivityLease + receiverRetryInterval)
		synctest.Wait()
		if starts.Load() != 1 || r.conn != nil {
			t.Fatal("background recovery reopened reception")
		}
		if r.pending[requestID{1}] != pending || len(r.deleted) != 1 || r.ctx.Err() != nil {
			t.Fatal("backgrounding discarded requests, tombstones or approval context")
		}
		if err := e.setReceiverActivity(true); err != nil {
			t.Fatal(err)
		}
		newSocket := <-resumed
		synctest.Wait()
		if receiverOf(e) != r || newSocket == socket || starts.Load() != 1 {
			t.Fatal("foregrounding did not resume the same request store with a fresh socket")
		}
		// A missing stop (app death or suspension) must still close reception.
		time.Sleep(receiverActivityLease)
		synctest.Wait()
		if _, err := newSocket.WriteToUDP([]byte{0}, src); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expired foreground lease left socket open: %v", err)
		}
	})
}

func TestForegroundLeaseRenewalDoesNotRejoinAndDesktopIgnoresActivity(t *testing.T) {
	for _, needsLease := range []bool{true, false} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			e := &extension{acceptRequests: true, ctx: ctx, cancel: cancel, logf: t.Logf, receiverNeedsLease: needsLease,
				receiverDone: make(chan struct{}), receiverControl: make(chan struct{}, 1)}
			t.Cleanup(func() { e.Shutdown() })
			e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
				r := testReceiver(t)
				r.conn = testSocket(t)
				r.pc = &testMulticastGroups{}
				return r, nil
			}
			e.setReceiverActivity(true)
			go e.runReceiver(make(chan struct{}))
			synctest.Wait()
			r := receiverOf(e)
			socket := r.conn
			time.Sleep(receiverActivityLease / 2)
			e.setReceiverActivity(true)
			synctest.Wait()
			time.Sleep(receiverActivityLease / 2)
			synctest.Wait()
			if r.conn != socket || len(r.pc.(*testMulticastGroups).joins) != 0 {
				t.Fatal("renewal restarted reception or failed to extend the lease")
			}
			if !needsLease {
				e.setReceiverActivity(false)
				synctest.Wait()
				time.Sleep(2 * receiverActivityLease)
				synctest.Wait()
				if r.conn != socket {
					t.Fatal("GUI activity disabled desktop reception")
				}
			}
		})
	}
}

func TestPausingDiscoveryDoesNotCancelInFlightApproval(t *testing.T) {
	s, r := testSender(t), testReceiver(t)
	s.conn = testSocket(t)
	r.conn = testSocket(t)
	r.pc = &testMulticastGroups{}
	r.wg.Add(1)
	go r.recvLoop(r.conn)
	t.Cleanup(r.Stop)
	testAdvertise(t, r, &beaconMsg{RequestID: s.sessRID, SenderEphPub: s.sessKey.pub, UnixSec: time.Now().Unix()}, s.conn.LocalAddr().(*net.UDPAddr))
	received, reply := make(chan struct{}), make(chan struct{})
	served := make(chan error, 1)
	go func() {
		buf := make([]byte, maxWireSize)
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
		close(received)
		<-reply
		packet, err := s.approvalResponse(approval)
		if err == nil {
			_, err = s.conn.WriteToUDP(packet, src)
		}
		served <- err
	}()
	result := make(chan error, 1)
	go func() {
		url, err := r.Approve(t.Context(), [16]byte(s.sessRID))
		if err == nil && url != s.sessURL {
			err = errors.New("wrong URL")
		}
		result <- err
	}()
	select {
	case <-received:
	case err := <-served:
		t.Fatalf("approval not received: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("approval did not start")
	}
	r.pause()
	if r.ctx.Err() != nil || r.conn != nil {
		t.Fatal("pause did not stop only discovery")
	}
	close(reply)
	if err := <-served; err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("pause cancelled in-flight approval: %v", err)
	}
}

func TestReceptionDefaultsAndPolicy(t *testing.T) {
	e := testExtension(t)
	policy := policytest.Config{}
	e.polc = policy
	starts := 0
	e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
		starts++
		r := testReceiver(t)
		r.conn = testSocket(t)
		return r, nil
	}
	prefs := ipn.NewPrefs()
	e.onProfileStateChange(ipn.LoginProfileView{}, prefs.View(), true)
	e.updatePolicy()
	if err := e.refreshReceiver(false); err != nil || starts != 1 {
		t.Fatalf("default reception: %v starts=%d", err, starts)
	}
	r := e.receiver
	testAdvertise(t, r, &beaconMsg{RequestID: requestID{1}, UnixSec: time.Now().Unix()}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	canceled := false
	r.pending[requestID{1}].cancel = func() { canceled = true }
	policy[pkey.AllowLoginBeacon] = false
	e.updatePolicy()
	if !canceled || len(r.pending) != 0 {
		t.Fatal("policy did not immediately clear requests")
	}
	if _, err := e.approve(t.Context(), [16]byte{1}); !errors.Is(err, errReceptionDisabled) {
		t.Fatal("policy allowed approval")
	}
	if err := e.testBroadcast(true, ""); !errors.Is(err, errPolicyDenied) {
		t.Fatal("policy allowed explicit sending")
	}
	testAdvertise(t, r, &beaconMsg{RequestID: requestID{2}, UnixSec: time.Now().Unix()}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234})
	if len(r.pending) != 0 {
		t.Fatal("revoked receiver admitted new request before socket cleanup")
	}
	if err := e.refreshReceiver(false); err != nil || e.receiver != nil {
		t.Fatal("policy did not close receiver")
	}
	delete(policy, pkey.AllowLoginBeacon)
	e.updatePolicy()
	if err := e.refreshReceiver(false); err != nil || starts != 2 {
		t.Fatal("permission did not restore reception")
	}
	prefs.AcceptLoginRequests = false
	e.onProfileStateChange(ipn.LoginProfileView{}, prefs.View(), true)
	if err := e.refreshReceiver(false); err != nil || e.receiver != nil {
		t.Fatal("user opt out did not stop reception")
	}
	policy[pkey.AllowLoginBeacon] = true
	e.updatePolicy()
	if err := e.refreshReceiver(false); err != nil || starts != 2 {
		t.Fatal("MDM true overrode user opt out")
	}
}

func TestReceiverSetupCannotUndoRevocation(t *testing.T) {
	for _, resume := range []bool{false, true} {
		t.Run(fmt.Sprintf("resume=%v", resume), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := testExtension(t)
				e.acceptRequests = true
				created := testReceiver(t)
				started, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
				e.newReceiver = func(context.Context, ReceiverConfig) (*Receiver, error) {
					close(started)
					<-release
					created.conn = testSocket(t)
					return created, nil
				}
				if resume {
					e.receiver = created
					e.resumeReceiver = func(*Receiver) error {
						_, err := e.newReceiver(e.ctx, ReceiverConfig{})
						return err
					}
				}
				go func() { finished <- e.refreshReceiver(false) }()
				<-started
				// Off then on still invalidates setup started before revocation.
				e.onProfileStateChange(ipn.LoginProfileView{}, (&ipn.Prefs{}).View(), true)
				e.onProfileStateChange(ipn.LoginProfileView{}, (&ipn.Prefs{AcceptLoginRequests: true}).View(), true)
				close(release)
				if err := <-finished; err != nil {
					t.Fatal(err)
				}
				if !resume {
					if e.receiver != nil || created.ctx.Err() == nil {
						t.Fatal("stale receiver was published instead of closed")
					}
				} else {
					if e.receiving || !created.disabled {
						t.Fatal("stale resume undid request revocation")
					}
					if err := e.refreshReceiver(false); err != nil || !e.receiving || created.disabled {
						t.Fatal("subsequent valid refresh did not enable reception")
					}
				}
			})
		})
	}
}
