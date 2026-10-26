// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

// Policy-enforcement tests: a material policy change closes the whole
// connection. New session channels and all four forwarding gates
// re-evaluate the policy before running. RuleExpires arms a conn-level
// timer, and the login-grace timer closes conns that never complete
// auth.

package tailssh

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/envknob"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
	"tailscale.com/types/netmap"
)

// policyFlipper is a localState whose matching rule can be swapped at
// runtime. NetMap reads it under a lock, so mid-flow policy flips are
// race-free against the concurrent policy re-evaluations from
// OnPolicyChange's kick, the auth-completion recheck, and the session
// and forward gates. onNoise, if set, runs before serving a delegate
// action and is used to swap the policy mid-HoldAndDelegate.
type policyFlipper struct {
	*localState

	mu   sync.Mutex
	rule *tailcfg.SSHRule

	onNoise func()
}

func (p *policyFlipper) setRule(r *tailcfg.SSHRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rule = r
}

func (p *policyFlipper) NetMap() *netmap.NetworkMap {
	p.mu.Lock()
	var policy *tailcfg.SSHPolicy
	if p.rule != nil {
		policy = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{p.rule}}
	}
	p.mu.Unlock()
	return &netmap.NetworkMap{
		SelfNode:  (&tailcfg.Node{ID: 1}).View(),
		SSHPolicy: policy,
	}
}

func (p *policyFlipper) NetMapNoPeers() *netmap.NetworkMap { return p.NetMap() }

func (p *policyFlipper) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	if p.onNoise != nil {
		p.onNoise()
	}
	return p.localState.DoNoiseRequest(req)
}

// newPolicyRule returns a rule granting the sshUser alice access as lu
// with the given action, matching any principal.
func newPolicyRule(action *tailcfg.SSHAction, lu *userMeta) *tailcfg.SSHRule {
	return &tailcfg.SSHRule{
		SSHUsers:   map[string]string{"alice": lu.Username},
		Action:     action,
		Principals: []*tailcfg.SSHPrincipal{{Any: true}},
	}
}

// startPolicyConn accepts a connection without starting client authentication.
func startPolicyConn(t *testing.T, p *policyFlipper) (*server, net.Conn, <-chan struct{}) {
	t.Helper()
	s := &server{logf: tstest.WhileTestRunningLogger(t), lb: p}
	t.Cleanup(s.Shutdown)
	src, dst := netip.MustParseAddrPort("100.100.100.101:2231"), netip.MustParseAddrPort("100.100.100.102:22")
	sc, dc := memnet.NewTCPConn(src, dst, 4096)
	t.Cleanup(func() { sc.Close() })
	if err := sc.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.HandleSSHConn(dc); err != nil {
			t.Errorf("HandleSSHConn: %v", err)
		}
	}()
	return s, sc, done
}

func dialPolicyConn(t *testing.T, p *policyFlipper) (*server, *testssh.Client, <-chan struct{}) {
	t.Helper()
	s, client, done, err := tryDialPolicyConn(t, p)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	// NewClientConn can return before the asynchronous auth-completion
	// policy check. Drain it before a test flips policy to exercise a gate.
	s.mu.Lock()
	var c *conn
	for c = range s.activeConns {
	}
	s.mu.Unlock()
	if c == nil {
		t.Fatal("connection disappeared after authentication")
	}
	select {
	case <-c.authRecheckDone:
	case <-time.After(10 * time.Second):
		t.Fatal("auth-completion policy check did not finish")
	}
	return s, client, done
}

// tryDialPolicyConn also allows tests to assert rejection during authentication.
func tryDialPolicyConn(t *testing.T, p *policyFlipper) (*server, *testssh.Client, <-chan struct{}, error) {
	t.Helper()
	s, sc, done := startPolicyConn(t, p)
	cl, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), &testssh.ClientConfig{
		User: "alice", HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return s, nil, done, err
	}
	client := testssh.NewClient(cl, chans, reqs)
	t.Cleanup(func() { client.Close() })
	return s, client, done, nil
}

// eventually polls cond every 25ms until it holds or d elapses, failing
// the test with msg otherwise.
func eventually(t *testing.T, d time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal(msg)
}

// sessionFails reports whether opening a new session channel on the
// client fails, as it does once the transport is down. Errors are
// expected, not logged.
func sessionFails(client *testssh.Client) bool {
	sess, err := client.NewSession()
	if err != nil {
		return true
	}
	sess.Close()
	return false
}

// sessionTestUser returns the local user the session-running tests map
// alice to. Under root that is root itself, because the direct-exec
// fallback refuses to run a non-root user's session as root. Otherwise
// it is fwdTestIdentity's non-root case.
func sessionTestUser(t *testing.T) *userMeta {
	t.Helper()
	if os.Geteuid() == 0 {
		lu, err := userLookup("root")
		if err != nil {
			t.Skipf("no local root user: %v", err)
		}
		return lu
	}
	return fwdTestIdentity(t)
}

// TestSSHRevokeMidSessionClosesConn pins mid-session revocation closing
// the conn. An authed conn running a session, whose policy flips to
// Reject, gets the whole connection closed by OnPolicyChange. A client
// attempting a fresh session channel sees transport failure, never the
// stale Accept.
func TestSSHRevokeMidSessionClosesConn(t *testing.T) {
	lu := sessionTestUser(t)
	accept := &tailcfg.SSHAction{Accept: true}
	reject := &tailcfg.SSHAction{Reject: true}
	p := &policyFlipper{
		localState: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
		},
		rule: newPolicyRule(accept, lu),
	}
	s, client, handleConnDone := dialPolicyConn(t, p)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	if err := sess.Start("sleep 30"); err != nil {
		t.Fatalf("session start: %v", err)
	}
	t.Cleanup(func() { sess.Close() })

	// Revoke mid-session. The rule flips to Reject and the policy-change
	// kick fires.
	p.setRule(newPolicyRule(reject, lu))
	s.OnPolicyChange()

	// The whole connection goes down. The running session's Wait errors
	// via its canceled ctx. The transport closes. A fresh session
	// channel fails instead of running under the stale Accept.
	sessErr := make(chan error, 1)
	go func() { sessErr <- sess.Wait() }()
	select {
	case err := <-sessErr:
		if err == nil {
			t.Fatal("revoked session Wait returned nil; want error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session not killed after policy revocation")
	}
	eventually(t, 10*time.Second, "connection not closed after policy revocation", func() bool {
		return sessionFails(client)
	})
	select {
	case <-handleConnDone:
	case <-time.After(10 * time.Second):
		t.Fatal("server side of revoked connection did not return")
	}
}

// TestSSHNarrowingClosesForwardOnlyConn pins narrowing for a
// forwarding-only conn with no sessions. Narrowing
// AllowLocalPortForwarding mid-conn closes the connection and its
// established forward. A pure extension, false to true, leaves the conn
// alive.
func TestSSHNarrowingClosesForwardOnlyConn(t *testing.T) {
	// TCP -L dials now use the credentialed monitor child, like -R binds.
	exe := makeExecutableReachable(t)
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	tstest.Replace(t, &monitorSpawnPrefix, testMonitorPrefix)

	// A local TCP service to -L forward to.
	svc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	go func() {
		for {
			nc, err := svc.Accept()
			if err != nil {
				return
			}
			nc.(interface{ SetDeadline(time.Time) error }).SetDeadline(time.Now().Add(30 * time.Second))
			go func() {
				defer nc.Close()
				io.Copy(nc, nc) // echo
			}()
		}
	}()

	lu := sessionTestUser(t)
	allow := &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true}
	p := &policyFlipper{
		localState: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
		},
		rule: newPolicyRule(allow, lu),
	}
	s, client, _ := dialPolicyConn(t, p)
	s.tailscaledPath = exe

	// Establish a live -L forward with no session channel anywhere.
	fwd, err := client.Dial("tcp", svc.Addr().String())
	if err != nil {
		t.Fatalf("forward dial: %v", err)
	}
	const msg = "through the forward"
	if _, err := fwd.Write([]byte(msg)); err != nil {
		t.Fatalf("write through forward: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(fwd, got); err != nil {
		t.Fatalf("read through forward: %v", err)
	}

	// The rule still accepts the user but now denies forwarding.
	p.setRule(newPolicyRule(&tailcfg.SSHAction{Accept: true}, lu))
	s.OnPolicyChange()

	// Both the established forward and its SSH transport close.
	fwdErr := make(chan error, 1)
	go func() {
		_, err := fwd.Read(got)
		fwdErr <- err
	}()
	select {
	case err := <-fwdErr:
		if err == nil {
			t.Fatal("established forward still alive after narrowing")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("established forward not torn down after narrowing")
	}
	// Wait for transport shutdown rather than racing NewSession against
	// the test client's mux teardown (which can strand a channel-open wait).
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Wait() }()
	select {
	case err := <-clientDone:
		if err == nil {
			t.Fatal("client Wait returned nil after policy revocation")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("connection not closed after narrowing")
	}
}

// TestSSHRevokeClosesReverseForwardListener pins the forwarding-only
// revocation case on the -R path. A conn with no sessions whose policy
// flips to Reject gets the whole connection closed. The monitor-bound
// reverse-forward listener dies with it and stops accepting.
func TestSSHRevokeClosesReverseForwardListener(t *testing.T) {
	lu := sessionTestUser(t)
	// The reverse bind goes through the conn's lazily spawned monitor.
	// Install the monitor seams before the first forward request.
	exe := makeExecutableReachable(t)
	t.Setenv("TS_TEST_SSH_FWD_PREFIX", strings.Join(testFwdPrefix, " "))
	old := monitorSpawnPrefix
	monitorSpawnPrefix = testMonitorPrefix
	t.Cleanup(func() { monitorSpawnPrefix = old })

	allow := &tailcfg.SSHAction{Accept: true, AllowRemotePortForwarding: true}
	p := &policyFlipper{
		localState: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
		},
		rule: newPolicyRule(allow, lu),
	}
	s, client, _ := dialPolicyConn(t, p)
	// The conn shares this server pointer: the monitor spawns lazily on
	// the first forward request, so the reachable copy must be in place
	// before then. The fwd children run as the bound user, and under a
	// root run they can exec the copy but not the original.
	s.tailscaledPath = exe

	ln, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reverse forward (tcpip-forward): %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	fwdAddr := ln.Addr().String()

	// Each successful dial makes the server open a forwarded-tcpip channel
	// to the client, and the client's per-forward queue holds only one. A
	// second pending connection blocks its forwarding goroutine with the
	// forward-list lock held by x/crypto/ssh's forwardList and wedges
	// the listener's Close at cleanup. Drain every dial.
	drain := func() {
		acc := make(chan net.Conn, 1)
		go func() {
			c, err := ln.Accept()
			if err == nil {
				acc <- c
			}
		}()
		select {
		case c := <-acc:
			c.Close()
		case <-time.After(time.Second):
		}
	}

	// The bound listener accepts before revocation.
	if tc, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second); err != nil {
		t.Fatalf("dial forwarded listener %s: %v", fwdAddr, err)
	} else {
		tc.Close()
		drain()
	}

	// Revoke. The rule flips to Reject and the kick closes the conn. The
	// listener must stop accepting via the gliderssh ctx cancel.
	p.setRule(newPolicyRule(&tailcfg.SSHAction{Reject: true}, lu))
	s.OnPolicyChange()

	eventually(t, 10*time.Second, "reverse-forward listener still accepting after revocation", func() bool {
		tc, err := net.DialTimeout("tcp", fwdAddr, 500*time.Millisecond)
		if err != nil {
			return true
		}
		tc.Close()
		drain()
		return false
	})
	eventually(t, 10*time.Second, "connection not closed after revocation", func() bool {
		return sessionFails(client)
	})
}

// TestSSHForwardExtensionKeepsConn pins the other direction of the
// material-change rule. Granting more, AllowLocalPortForwarding false
// to true, must not kill the live conn.
func TestSSHForwardExtensionKeepsConn(t *testing.T) {
	lu := sessionTestUser(t)
	p := &policyFlipper{localState: &localState{sshEnabled: true, varRoot: t.TempDir()},
		rule: newPolicyRule(&tailcfg.SSHAction{Accept: true}, lu)}
	s, client, _ := dialPolicyConn(t, p)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	if out, err := sess.CombinedOutput("echo ok"); err != nil || string(out) == "" {
		t.Fatalf("first session: %q, %v", out, err)
	}
	sess.Close()

	// Pure extension. The conn must survive and keep serving sessions.
	p.setRule(newPolicyRule(&tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true}, lu))
	s.OnPolicyChange()
	time.Sleep(200 * time.Millisecond) // a kick, if one fired, lands here
	sess2, err := client.NewSession()
	if err != nil {
		t.Fatalf("session after extension: %v (conn should have stayed up)", err)
	}
	sess2.Close()
}

// TestSSHPolicyMappedUIDRecheck exercises auth-time latching with a policy
// mapping by UID, which userLookup resolves to a canonical username.
func TestSSHPolicyMappedUIDRecheck(t *testing.T) {
	lu := sessionTestUser(t)
	resolved, err := userLookup(lu.Uid)
	if err != nil || resolved.Username != lu.Username || resolved.Uid != lu.Uid || lu.Uid == lu.Username {
		t.Skipf("local UID %q cannot be used as a canonicalizing policy mapping: user=%v, err=%v", lu.Uid, resolved, err)
	}
	p := &policyFlipper{
		localState: &localState{sshEnabled: true, varRoot: t.TempDir()},
		rule: &tailcfg.SSHRule{
			SSHUsers:   map[string]string{"alice": lu.Uid},
			Action:     &tailcfg.SSHAction{Accept: true},
			Principals: []*tailcfg.SSHPrincipal{{Any: true}},
		},
	}
	srv, client, _ := dialPolicyConn(t, p)
	srv.mu.Lock()
	var c *conn
	for c = range srv.activeConns {
	}
	srv.mu.Unlock()
	if c == nil {
		t.Fatal("authenticated connection missing")
	}
	if c.mappedLocalUser != lu.Uid || c.localUser.Username != lu.Username {
		t.Fatalf("latched mapping = %q, resolved user = %q; want %q and %q", c.mappedLocalUser, c.localUser.Username, lu.Uid, lu.Username)
	}
	if !c.recheckPolicy() {
		t.Fatal("unchanged UID mapping revoked the connection")
	}
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session after unchanged UID mapping: %v", err)
	}
	sess.Close()
}

// TestSSHStaleLocalUserClosed pins the stale-action guard. When the
// policy re-maps the ssh user to a different local user, a new session
// channel on the old conn is refused and the conn closed. It never runs
// under the old latched localUser.
func TestSSHStaleLocalUserClosed(t *testing.T) {
	lu := sessionTestUser(t)
	other := "root"
	if lu.Username == "root" {
		other = "daemon"
	}
	p := &policyFlipper{localState: &localState{sshEnabled: true, varRoot: t.TempDir()},
		rule: newPolicyRule(&tailcfg.SSHAction{Accept: true}, lu)}
	_, client, _ := dialPolicyConn(t, p)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("first session: %v", err)
	}
	sess.Close()

	// Re-map alice to a different local user and open a NEW session.
	p.setRule(&tailcfg.SSHRule{
		SSHUsers:   map[string]string{"alice": other},
		Action:     &tailcfg.SSHAction{Accept: true},
		Principals: []*tailcfg.SSHPrincipal{{Any: true}},
	})
	sess2, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session channel: %v", err)
	}
	// The session must not run under the stale local user. It is refused
	// with the revocation notice and SSH-layer exit 255. The conn is
	// closed, asserted below.
	out, err := sess2.CombinedOutput("echo should-not-run")
	if err == nil {
		t.Fatalf("new session ran under stale local user (out=%q); want refusal", out)
	}
	if !strings.Contains(string(out), "access revoked") {
		t.Errorf("refusal output = %q; want access-revoked notice", out)
	}
	var exitErr *testssh.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitStatus() != 255 {
		t.Errorf("refusal error = %v; want exit status 255 (SSH-layer failure), got %v", err, exitErr)
	}
	eventually(t, 10*time.Second, "connection not closed after local-user change", func() bool {
		return sessionFails(client)
	})
}

// TestSSHHoldAndDelegateCompletionRecheck pins the auth-completion
// recheck. A conn that completes HoldAndDelegate auth with unchanged
// policy proceeds normally. One whose policy was revoked while the
// delegate fetch was in flight is closed at completion.
func TestSSHHoldAndDelegateCompletionRecheck(t *testing.T) {
	lu := sessionTestUser(t)
	holdRule := func(action *tailcfg.SSHAction) *tailcfg.SSHRule {
		return &tailcfg.SSHRule{
			SSHUsers:   map[string]string{"alice": lu.Username},
			Action:     action,
			Principals: []*tailcfg.SSHPrincipal{{Any: true}},
		}
	}

	t.Run("unchanged-policy-proceeds", func(t *testing.T) {
		p := &policyFlipper{
			localState: &localState{
				sshEnabled:    true,
				varRoot:       t.TempDir(),
				serverActions: map[string]*tailcfg.SSHAction{"accept": {Accept: true}},
			},
			rule: holdRule(&tailcfg.SSHAction{HoldAndDelegate: "https://unused/ssh-action/accept"}),
		}
		_, client, _ := dialPolicyConn(t, p)
		sess, err := client.NewSession()
		if err != nil {
			t.Fatalf("unchanged policy rejected session after delegation: %v", err)
		}
		sess.Close()
	})

	t.Run("revoked-during-delegate-closes", func(t *testing.T) {
		p := &policyFlipper{
			localState: &localState{
				sshEnabled:    true,
				varRoot:       t.TempDir(),
				serverActions: map[string]*tailcfg.SSHAction{"accept": {Accept: true}},
			},
			rule: holdRule(&tailcfg.SSHAction{HoldAndDelegate: "https://unused/ssh-action/accept"}),
		}
		// Revoke the netmap rule while the delegate fetch is in flight
		// and control still answers "accept". The auth-completion
		// recheck must close the conn at completion.
		p.onNoise = func() {
			p.setRule(holdRule(&tailcfg.SSHAction{Reject: true}))
		}
		_, client, handleConnDone, err := tryDialPolicyConn(t, p)
		if err == nil {
			eventually(t, 10*time.Second, "conn that authed against a revoked rule stayed up", func() bool {
				return sessionFails(client)
			})
		}
		select {
		case <-handleConnDone:
		case <-time.After(10 * time.Second):
			t.Fatal("server side of revoked hold conn did not return")
		}
	})
}

// TestSSHRuleExpiryClosesConn pins the conn-level RuleExpires timer. A
// rule whose expiry lands 2s after auth closes the conn at expiry,
// because the fresh evaluation fails closed on the expired rule. The
// expiry is set after auth, like TestSSHRuleExpiryRearmsOnFreshMatch:
// the 2s window starts before the host key generation and the
// handshake otherwise, so on a slow runner the rule could already be
// expired when the conn auths.
func TestSSHRuleExpiryClosesConn(t *testing.T) {
	lu := sessionTestUser(t)
	accept := &tailcfg.SSHAction{Accept: true}
	p := &policyFlipper{
		localState: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
		},
		rule: newPolicyRule(accept, lu),
	}
	s, client, _ := dialPolicyConn(t, p)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session before expiry: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	if err := sess.Start("sleep 30"); err != nil {
		t.Fatalf("session start: %v", err)
	}

	// Auth is complete. Arm the expiry now: the fresh rule matches
	// identically, so the kick's re-evaluation is non-material and only
	// the armed timer closes the conn, 2s in.
	exp := time.Now().Add(2 * time.Second)
	fresh := newPolicyRule(accept, lu)
	fresh.RuleExpires = &exp
	p.setRule(fresh)
	s.OnPolicyChange()

	// The expiry timer fires ~2s in. Eval fails closed on the expired
	// rule and the conn closes.
	eventually(t, 10*time.Second, "conn with expired rule stayed up", func() bool {
		return sessionFails(client)
	})
	sessErr := make(chan error, 1)
	go func() { sessErr <- sess.Wait() }()
	select {
	case err := <-sessErr:
		if err == nil {
			t.Fatal("session on expired-rule conn returned nil; want error")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("session on expired-rule conn not killed")
	}
}

// TestSSHRuleExpiryRearmsOnFreshMatch pins the ruleTimer re-arm. A
// mid-conn policy edit whose fresh matched rule carries a RuleExpires is
// non-material at edit time, because the grant is unchanged. The
// conn-level timer must then be re-armed to the fresh rule's expiry.
func TestSSHRuleExpiryRearmsOnFreshMatch(t *testing.T) {
	lu := sessionTestUser(t)
	accept := &tailcfg.SSHAction{Accept: true}
	// The auth-time rule has no expiry.
	p := &policyFlipper{
		localState: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
		},
		rule: newPolicyRule(accept, lu),
	}
	s, client, _ := dialPolicyConn(t, p)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	if err := sess.Start("sleep 30"); err != nil {
		t.Fatalf("session start: %v", err)
	}

	// Mid-conn edit. The grant is the same, but the fresh rule expires in
	// 5s. The kick's re-evaluation is non-material with an identical
	// action, so only the re-armed timer closes the conn at the new
	// expiry.
	exp := time.Now().Add(5 * time.Second)
	fresh := newPolicyRule(accept, lu)
	fresh.RuleExpires = &exp
	p.setRule(fresh)
	s.OnPolicyChange()

	// The re-evaluation was non-material, so the conn must survive the
	// immediate kick.
	time.Sleep(500 * time.Millisecond)
	if sessionFails(client) {
		t.Fatal("conn closed immediately after a non-material policy edit")
	}
	// It must also close at the rearmed rule's expiry.
	eventually(t, 15*time.Second, "conn stayed up past the rearmed rule's expiry", func() bool {
		return sessionFails(client)
	})
}

// TestSSHLoginGraceTimeExpires pins the pre-auth grace timer, in parity
// with sshd's LoginGraceTime. A conn that never completes auth is closed
// at the deadline, shortened for this test. Authed conns are unaffected;
// every other test in this package auths within the default 120s.
func TestSSHLoginGraceTimeExpires(t *testing.T) {
	envknob.SetenvForTest(t, "TS_SSH_LOGIN_GRACE_TIME", "250ms")
	s := &server{logf: t.Logf, lb: &localState{sshEnabled: true, varRoot: t.TempDir()}}
	src, dst := netip.MustParseAddrPort("100.100.100.101:2231"), netip.MustParseAddrPort("100.100.100.102:22")
	sc, dc := memnet.NewTCPConn(src, dst, 1024)
	defer sc.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.HandleSSHConn(dc); err != nil {
			t.Errorf("HandleSSHConn: %v", err)
		}
	}()
	// The client never sends a byte. The handshake blocks on its first
	// read until the grace timer closes the raw conn.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("conn that never completed auth was not closed at the grace deadline")
	}
}

// TestMaterialPolicyChange pins the material-change definition field by
// field on synthetic conns. Every privilege and monitoring reduction
// closes. Every pure extension does not.
func TestMaterialPolicyChange(t *testing.T) {
	lu := sessionTestUser(t)
	currentUser := lu.Username
	addr := netip.MustParseAddrPort("127.0.0.1:1")

	rule := func(a *tailcfg.SSHAction, acceptEnv []string) *tailcfg.SSHRule {
		return &tailcfg.SSHRule{
			SSHUsers:   map[string]string{"alice": currentUser},
			Action:     a,
			AcceptEnv:  acceptEnv,
			Principals: []*tailcfg.SSHPrincipal{{Any: true}},
		}
	}
	accept := func(mod func(*tailcfg.SSHAction)) *tailcfg.SSHAction {
		a := &tailcfg.SSHAction{Accept: true}
		if mod != nil {
			mod(a)
		}
		return a
	}

	tests := []struct {
		name     string
		latched  *tailcfg.SSHAction // what the conn authed with
		latchEnv []string           // acceptEnv latched at auth
		fresh    *tailcfg.SSHAction
		freshEnv []string
		want     bool
	}{
		{name: "unchanged", latched: accept(nil), fresh: accept(nil), want: false},
		{name: "reject", latched: accept(nil), fresh: &tailcfg.SSHAction{Reject: true}, want: true},
		{
			name:    "accept-to-hold",
			latched: accept(nil),
			fresh:   &tailcfg.SSHAction{HoldAndDelegate: "https://unused/ssh-action/x"},
			want:    true,
		},
		{
			// The fresh rule still requires delegation. For a conn that
			// already went through delegation, action0 was the hold that
			// control answered with this conn's finalAction. Control's
			// grant stands, so it is not material; the loop below gives
			// this case its action0.
			name:    "hold-unchanged-for-delegated-conn",
			latched: accept(nil),
			fresh:   &tailcfg.SSHAction{HoldAndDelegate: "https://unused/ssh-action/x"},
			want:    false,
		},
		{
			name:    "forwarding-flag-narrowed",
			latched: accept(func(a *tailcfg.SSHAction) { a.AllowLocalPortForwarding = true }),
			fresh:   accept(nil),
			want:    true,
		},
		{
			name:    "forwarding-flag-extension",
			latched: accept(nil),
			fresh:   accept(func(a *tailcfg.SSHAction) { a.AllowLocalPortForwarding = true }),
			want:    false,
		},
		{
			name:    "recorder-removed",
			latched: accept(func(a *tailcfg.SSHAction) { a.Recorders = []netip.AddrPort{addr} }),
			fresh:   accept(nil),
			want:    true,
		},
		{
			name:    "recorder-added",
			latched: accept(nil),
			fresh:   accept(func(a *tailcfg.SSHAction) { a.Recorders = []netip.AddrPort{addr} }),
			want:    true,
		},
		{
			name: "recording-failure-narrowed",
			latched: accept(func(a *tailcfg.SSHAction) {
				a.OnRecordingFailure = &tailcfg.SSHRecorderFailureAction{TerminateSessionWithMessage: "x"}
			}),
			fresh: accept(nil),
			want:  true,
		},
		{
			name:    "duration-shortened",
			latched: accept(func(a *tailcfg.SSHAction) { a.SessionDuration = time.Minute }),
			fresh:   accept(func(a *tailcfg.SSHAction) { a.SessionDuration = 10 * time.Second }),
			want:    true,
		},
		{
			name:    "duration-extended",
			latched: accept(func(a *tailcfg.SSHAction) { a.SessionDuration = 10 * time.Second }),
			fresh:   accept(func(a *tailcfg.SSHAction) { a.SessionDuration = time.Minute }),
			want:    false,
		},
		{
			name:    "duration-uncapped",
			latched: accept(func(a *tailcfg.SSHAction) { a.SessionDuration = 10 * time.Second }),
			fresh:   accept(nil),
			want:    false,
		},
		{
			name:     "acceptenv-narrowed",
			latched:  accept(nil),
			latchEnv: []string{"FOO_*"},
			fresh:    accept(nil),
			freshEnv: []string{"FOO_1"},
			want:     true,
		},
		{
			name:     "acceptenv-extension",
			latched:  accept(nil),
			latchEnv: []string{"FOO_1"},
			fresh:    accept(nil),
			freshEnv: []string{"FOO_*"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &policyFlipper{localState: &localState{sshEnabled: true, varRoot: t.TempDir()},
				rule: rule(tt.fresh, tt.freshEnv)}
			c := &conn{
				srv:             &server{logf: t.Logf, lb: p},
				action0:         tt.latched,
				finalAction:     tt.latched,
				acceptEnv:       tt.latchEnv,
				localUser:       lu,
				mappedLocalUser: lu.Username,
				info: &sshConnInfo{
					sshUser: "alice",
					src:     netip.MustParseAddrPort("1.2.3.4:30343"),
					dst:     netip.MustParseAddrPort("100.100.100.102:22"),
				},
			}
			if tt.name == "hold-unchanged-for-delegated-conn" {
				// The conn went through delegation. Action0 was the hold.
				c.action0 = &tailcfg.SSHAction{HoldAndDelegate: "https://unused/ssh-action/x"}
			}
			got, why, _ := c.materialPolicyChange()
			if got != tt.want {
				t.Errorf("materialPolicyChange = %v (%q); want %v", got, why, tt.want)
			}
		})
	}
	// A localUser change is material even when the fresh rule still
	// accepts and the fresh user resolves.
	t.Run("local-user-changed", func(t *testing.T) {
		other := "root"
		if lu.Username == "root" {
			other = "daemon"
		}
		p := &policyFlipper{localState: &localState{sshEnabled: true, varRoot: t.TempDir()},
			rule: &tailcfg.SSHRule{
				SSHUsers:   map[string]string{"alice": other},
				Action:     &tailcfg.SSHAction{Accept: true},
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
			}}
		c := &conn{
			srv:             &server{logf: t.Logf, lb: p},
			action0:         &tailcfg.SSHAction{Accept: true},
			finalAction:     &tailcfg.SSHAction{Accept: true},
			localUser:       lu,
			mappedLocalUser: lu.Username,
			info: &sshConnInfo{
				sshUser: "alice",
				src:     netip.MustParseAddrPort("1.2.3.4:30343"),
				dst:     netip.MustParseAddrPort("100.100.100.102:22"),
			},
		}
		got, _, _ := c.materialPolicyChange()
		if !got {
			t.Error("localUser change not material")
		}
	})

	// An expired rule fails closed in evaluation, which the conn-level
	// timer relies on. The fresh evaluation rejects once the rule
	// expires.
	t.Run("expired-rule-fails-closed", func(t *testing.T) {
		exp := time.Now().Add(-time.Second)
		r := rule(&tailcfg.SSHAction{Accept: true}, nil)
		r.RuleExpires = &exp
		p := &policyFlipper{localState: &localState{sshEnabled: true, varRoot: t.TempDir()}, rule: r}
		c := &conn{
			srv:             &server{logf: t.Logf, lb: p},
			action0:         &tailcfg.SSHAction{Accept: true},
			finalAction:     &tailcfg.SSHAction{Accept: true},
			localUser:       lu,
			mappedLocalUser: lu.Username,
			info: &sshConnInfo{
				sshUser: "alice",
				src:     netip.MustParseAddrPort("1.2.3.4:30343"),
				dst:     netip.MustParseAddrPort("100.100.100.102:22"),
			},
		}
		got, _, _ := c.materialPolicyChange()
		if !got {
			t.Error("expired rule did not fail closed in fresh evaluation")
		}
	})
}

// TestSSHHoldDelegateGraceExtension checks that entering delegation replaces
// the initial grace timer, without imposing a short deadline on key exchange.
func TestSSHHoldDelegateGraceExtension(t *testing.T) {
	lu := sessionTestUser(t)
	p := &policyFlipper{
		localState: &localState{
			sshEnabled: true, varRoot: t.TempDir(),
			serverActions: map[string]*tailcfg.SSHAction{"accept": {Accept: true}},
		},
		rule: newPolicyRule(&tailcfg.SSHAction{HoldAndDelegate: "https://unused/ssh-action/accept"}, lu),
	}
	srv, sc, done := startPolicyConn(t, p)
	eventually(t, 10*time.Second, "connection not registered", func() bool { return srv.NumActiveConns() == 1 })
	srv.mu.Lock()
	var c *conn
	for c = range srv.activeConns {
	}
	srv.mu.Unlock()
	c.mu.Lock()
	initial := c.graceTimer
	c.mu.Unlock()
	called := make(chan struct{})
	p.onNoise = func() {
		c.mu.Lock()
		if c.graceTimer == nil || c.graceTimer == initial || c.authCompleted.Load() {
			t.Error("delegation did not replace the pre-auth grace timer")
		}
		c.mu.Unlock()
		close(called)
	}
	cl, _, _, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), &testssh.ClientConfig{
		User: "alice", HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	cl.Close()
	<-done
	select {
	case <-called:
	default:
		t.Fatal("delegate fetch did not run")
	}
}

// TestSSHRuleExpiryNotRearmedAfterTeardown pins the teardownDone guard.
// A recheck goroutine that completes after the conn's teardown, in
// stopConnTimers as deferred by HandleSSHConn, must not re-arm
// ruleTimer. The re-evaluation here is non-material, since the unchanged
// rule still matches, which is exactly the branch that re-arms.
func TestSSHRuleExpiryNotRearmedAfterTeardown(t *testing.T) {
	lu := sessionTestUser(t)
	accept := &tailcfg.SSHAction{Accept: true}
	exp := time.Now().Add(time.Hour) // far away: only the guard stops the arm
	rule := newPolicyRule(accept, lu)
	rule.RuleExpires = &exp
	p := &policyFlipper{localState: &localState{sshEnabled: true, varRoot: t.TempDir()}, rule: rule}
	s, client, _ := dialPolicyConn(t, p)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	if err := sess.Start("sleep 30"); err != nil {
		t.Fatalf("session start: %v", err)
	}

	// The live, authed conn.
	s.mu.Lock()
	var c *conn
	for cc := range s.activeConns {
		c = cc
	}
	s.mu.Unlock()
	if c == nil {
		t.Fatal("no active conn")
	}

	// Run the conn teardown, stopConnTimers, then the straggling
	// recheck. Its non-material branch must not re-arm the timer.
	c.stopConnTimers()
	if ok := c.recheckPolicy(); !ok {
		t.Fatal("recheckPolicy rejected an unchanged matching rule")
	}
	c.mu.Lock()
	rearmed := c.ruleTimer != nil
	c.mu.Unlock()
	if rearmed {
		t.Fatal("ruleTimer re-armed after stopConnTimers; want teardownDone to suppress the arm")
	}
}
