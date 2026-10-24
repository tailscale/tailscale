// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
)

func TestPolicyRecheckRestrictions(t *testing.T) {
	lu := sessionTestUser(t)
	recorder := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}
	hold := &tailcfg.SSHAction{HoldAndDelegate: "https://unused/hold"}
	src := netip.MustParseAddrPort("1.2.3.4:1234")
	dst := netip.MustParseAddrPort("100.100.100.102:22")
	tests := []struct {
		name    string
		initial *tailcfg.SSHAction
		old     *tailcfg.SSHAction
		fresh   *tailcfg.SSHAction
		oldEnv  []string
		want    bool
	}{
		{
			name: "duplicate-recorder-replaced",
			old: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: []netip.AddrPort{recorder[0], recorder[0]},
			},
			fresh: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: []netip.AddrPort{recorder[0], netip.MustParseAddrPort("127.0.0.1:2")},
			},
			want: true,
		},
		{
			name: "recording-fail-closed",
			old: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: recorder,
			},
			fresh: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: recorder,
				OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
					RejectSessionWithMessage:    "required",
					TerminateSessionWithMessage: "required",
				},
			},
			want: true,
		},
		{
			name:    "delegated-env-removed",
			old:     &tailcfg.SSHAction{Accept: true},
			initial: hold,
			fresh:   hold,
			oldEnv:  []string{"FOO_*"},
			want:    true,
		},
		{
			name:    "delegated-recording-added",
			old:     &tailcfg.SSHAction{Accept: true},
			initial: hold,
			fresh: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders:       recorder,
			},
			want: true,
		},
		{
			name: "delegated-failure-action-added",
			old:  &tailcfg.SSHAction{Accept: true},
			initial: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders:       recorder,
			},
			fresh: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders:       recorder,
				OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
					RejectSessionWithMessage: "required",
				},
			},
			want: true,
		},
		{
			name: "delegated-recorder-override",
			old: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: recorder,
			},
			initial: hold,
			fresh: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders: []netip.AddrPort{
					netip.MustParseAddrPort("127.0.0.1:2"),
				},
			},
		},
		{
			name: "forwarding-removed",
			old: &tailcfg.SSHAction{
				Accept:                   true,
				AllowLocalPortForwarding: true,
			},
			fresh: &tailcfg.SSHAction{Accept: true},
			want:  true,
		},
		{
			name: "duration-shortened",
			old:  &tailcfg.SSHAction{Accept: true},
			fresh: &tailcfg.SSHAction{
				Accept:          true,
				SessionDuration: time.Minute,
			},
			want: true,
		},
		{
			name:  "accept-to-hold",
			old:   &tailcfg.SSHAction{Accept: true},
			fresh: hold,
			want:  true,
		},
		{
			name:  "unchanged",
			old:   &tailcfg.SSHAction{Accept: true},
			fresh: &tailcfg.SSHAction{Accept: true},
		},
	}
	for _, tt := range tests {
		for _, lookupFails := range []bool{false, true} {
			name := fmt.Sprintf("%s/lookupFails=%v", tt.name, lookupFails)
			t.Run(name, func(t *testing.T) {
				initial := tt.initial
				if initial == nil {
					initial = tt.old
				}
				p := &policyFlipper{
					localState: &localState{sshEnabled: true},
					rule:       newPolicyRule(tt.fresh, lu),
				}
				c := &conn{
					srv: &server{
						logf: t.Logf,
						lb:   p,
					},
					localUser:       lu,
					mappedLocalUser: lu.Username,
					action0:         initial,
					finalAction:     tt.old,
					acceptEnv:       tt.oldEnv,
					info: &sshConnInfo{
						sshUser: "alice",
						src:     src,
						dst:     dst,
					},
				}
				lookup := userLookup
				if lookupFails {
					lookup = func(string) (*userMeta, error) {
						return nil, errors.New("lookup unavailable")
					}
				}
				changed, why, _ := c.materialPolicyChangeWithUserLookup(lookup)
				if changed != tt.want {
					t.Fatalf("material=%v (%s), want %v", changed, why, tt.want)
				}
			})
		}
	}
}

// TestPolicyRecheckMappedAliasIdentity covers policy spellings that look up
// to a different canonical username (for example a numeric UID or an alias).
func TestPolicyRecheckMappedAliasIdentity(t *testing.T) {
	canonical := &userMeta{User: user.User{Username: "canonical", Uid: "1001", Gid: "1001"}}
	tests := []struct {
		name        string
		mapping     string
		lookupUser  *userMeta
		lookupErr   error
		freshAction *tailcfg.SSHAction
		wantChange  bool
	}{
		{name: "unchanged-alias", mapping: "alias", lookupUser: canonical},
		{name: "remapped-alias-same-account", mapping: "other-alias", lookupUser: canonical, wantChange: true},
		{name: "uid-changed", mapping: "alias", lookupUser: &userMeta{User: user.User{Username: "canonical", Uid: "1002", Gid: "1001"}}, wantChange: true},
		{name: "canonical-name-changed", mapping: "alias", lookupUser: &userMeta{User: user.User{Username: "other", Uid: "1001", Gid: "1001"}}, wantChange: true},
		{name: "gid-changed", mapping: "alias", lookupUser: &userMeta{User: user.User{Username: "canonical", Uid: "1001", Gid: "1002"}}, wantChange: true},
		{name: "account-deleted", mapping: "alias", lookupErr: user.UnknownUserError("alias"), wantChange: true},
		{name: "nss-outage", mapping: "alias", lookupErr: errors.New("NSS temporarily unavailable")},
		{name: "nss-outage-forwarding-revoked", mapping: "alias", lookupErr: errors.New("NSS temporarily unavailable"), freshAction: &tailcfg.SSHAction{Accept: true}, wantChange: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			freshAction := tt.freshAction
			if freshAction == nil {
				freshAction = &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true}
			}
			p := &policyFlipper{
				localState: &localState{sshEnabled: true},
				rule: &tailcfg.SSHRule{
					SSHUsers:   map[string]string{"alice": tt.mapping},
					Action:     freshAction,
					Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				},
			}
			c := &conn{
				srv:             &server{logf: t.Logf, lb: p},
				localUser:       canonical,
				mappedLocalUser: "alias",
				action0:         &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
				finalAction:     &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true},
				info: &sshConnInfo{
					sshUser: "alice",
					src:     netip.MustParseAddrPort("1.2.3.4:1234"),
					dst:     netip.MustParseAddrPort("100.100.100.102:22"),
				},
			}
			lookedUp := false
			changed, why, _ := c.materialPolicyChangeWithUserLookup(func(name string) (*userMeta, error) {
				lookedUp = true
				if name != tt.mapping {
					t.Errorf("lookup argument = %q, want %q", name, tt.mapping)
				}
				return tt.lookupUser, tt.lookupErr
			})
			if changed != tt.wantChange {
				t.Errorf("material=%v (%s), want %v", changed, why, tt.wantChange)
			}
			if lookedUp != (tt.mapping == "alias") {
				t.Errorf("lookup called=%v for mapping %q", lookedUp, tt.mapping)
			}
		})
	}
}

// TestPolicyRecheckEqualMapping exercises the lookup during rule matching as
// well as the later identity check. Inconclusive results must not become a
// user mismatch, bypass other restrictions, or allow a root account.
func TestPolicyRecheckEqualMapping(t *testing.T) {
	alice := &userMeta{User: user.User{Username: "alice", Uid: "1001", Gid: "1001"}}
	root := &userMeta{User: user.User{Username: "root", Uid: "0", Gid: "0"}}
	for _, tt := range []struct {
		name             string
		old              *userMeta
		fresh            *userMeta
		err              error
		revokeForwarding bool
		want             bool
	}{
		{name: "unchanged", old: alice, fresh: alice},
		{name: "outage", old: alice, err: errors.New("getent unavailable")},
		{name: "outage-forwarding-revoked", old: alice, err: errors.New("getent unavailable"), revokeForwarding: true, want: true},
		{name: "deleted", old: alice, err: user.UnknownUserError("alice"), want: true},
		{name: "changed-to-root", old: alice, fresh: root, want: true},
		{name: "root-during-outage", old: root, err: errors.New("getent unavailable"), want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			old := &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true}
			fresh := &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: !tt.revokeForwarding}
			p := &policyFlipper{
				localState: &localState{sshEnabled: true},
				rule: &tailcfg.SSHRule{
					SSHUsers:   map[string]string{"*": "="},
					Principals: []*tailcfg.SSHPrincipal{{Any: true}},
					Action:     fresh,
				},
			}
			c := &conn{
				srv:       &server{logf: t.Logf, lb: p},
				localUser: tt.old, mappedLocalUser: "alice",
				action0: old, finalAction: old,
				info: &sshConnInfo{sshUser: "alice"},
			}
			calls := 0
			changed, why, _ := c.materialPolicyChangeWithUserLookup(func(name string) (*userMeta, error) {
				calls++
				if name != "alice" {
					t.Errorf("lookup(%q), want alice", name)
				}
				return tt.fresh, tt.err
			})
			if changed != tt.want {
				t.Errorf("material=%v (%s), want %v", changed, why, tt.want)
			}
			if calls != 1 {
				t.Errorf("lookup called %d times, want 1", calls)
			}
		})
	}
}

func TestForwardingDeniedBeforePolicyLookup(t *testing.T) {
	// No server: any attempt at policy evaluation would panic. A denied
	// channel must not do policy or account lookups, regardless of its type.
	for _, action := range []*tailcfg.SSHAction{nil, {Accept: true}} {
		c := &conn{finalAction: action}
		if c.mayForwardLocalPortTo(nil, "localhost", 80) {
			t.Error("local forwarding allowed")
		}
		if c.mayReversePortForwardTo(nil, "localhost", 80) {
			t.Error("remote forwarding allowed")
		}
		if _, err := c.mayForwardLocalUnixTo(nil, "/unused"); err == nil {
			t.Error("local Unix forwarding allowed")
		}
		if _, err := c.mayReverseUnixForwardTo(nil, "/unused"); err == nil {
			t.Error("remote Unix forwarding allowed")
		}
	}
}

func TestForwardingPolicyUsesLatchedIdentity(t *testing.T) {
	// This synthetic account cannot be looked up on the host. Even "="
	// rules must use the latched identity on the per-forward hot path.
	lu := &userMeta{User: user.User{Username: "tailscale-nonexistent-test-account", Uid: "1001", Gid: "1001"}}
	action := &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true, AllowRemotePortForwarding: true}
	p := &policyFlipper{localState: &localState{sshEnabled: true}, rule: &tailcfg.SSHRule{
		SSHUsers: map[string]string{"*": "="}, Action: action,
		Principals: []*tailcfg.SSHPrincipal{{Any: true}},
	}}
	c := &conn{srv: &server{logf: t.Logf, lb: p}, localUser: lu, mappedLocalUser: lu.Username,
		action0: action, finalAction: action, info: &sshConnInfo{sshUser: lu.Username}}
	defer c.stopConnTimers()
	if !c.mayForwardLocalPortTo(nil, "localhost", 80) {
		t.Fatal("local forwarding denied")
	}
	if !c.mayReversePortForwardTo(nil, "localhost", 80) {
		t.Fatal("remote forwarding denied")
	}
	p.setRule(&tailcfg.SSHRule{Action: &tailcfg.SSHAction{Reject: true}, Principals: []*tailcfg.SSHPrincipal{{Any: true}}})
	if c.recheckForwardingPolicy() {
		t.Fatal("revoked forwarding allowed")
	}
}

func TestRecordersChanged(t *testing.T) {
	a := netip.MustParseAddrPort("127.0.0.1:1")
	b := netip.MustParseAddrPort("127.0.0.1:2")
	for _, tt := range []struct {
		name       string
		old, fresh []netip.AddrPort
		want       bool
	}{
		{name: "empty", old: nil, fresh: []netip.AddrPort{}},
		{name: "added", fresh: []netip.AddrPort{a}, want: true},
		{name: "removed", old: []netip.AddrPort{a}, want: true},
		{name: "reordered", old: []netip.AddrPort{a, b}, fresh: []netip.AddrPort{b, a}},
		{name: "duplicate-replaced", old: []netip.AddrPort{a, a}, fresh: []netip.AddrPort{a, b}, want: true},
		{name: "duplicate-introduced", old: []netip.AddrPort{a, b}, fresh: []netip.AddrPort{a, a}, want: true},
		{name: "duplicate-counts-changed", old: []netip.AddrPort{a, a, b}, fresh: []netip.AddrPort{a, b, b}, want: true},
		{name: "duplicates-reordered", old: []netip.AddrPort{a, a, b}, fresh: []netip.AddrPort{b, a, a}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := recordersChanged(tt.old, tt.fresh); got != tt.want {
				t.Errorf("recordersChanged(%v, %v) = %v; want %v", tt.old, tt.fresh, got, tt.want)
			}
		})
	}
}

func TestRecordingFailureChange(t *testing.T) {
	old := &tailcfg.SSHRecorderFailureAction{NotifyURL: "https://control/old"}
	fresh := &tailcfg.SSHRecorderFailureAction{NotifyURL: "https://control/new"}
	if !recFailureChanged(old, fresh) {
		t.Error("changed notification destination ignored")
	}
	if recFailureChanged(nil, &tailcfg.SSHRecorderFailureAction{}) {
		t.Error("nil and empty actions differ")
	}
}

func TestIsUserMissing(t *testing.T) {
	if !isUserMissing(fmt.Errorf("lookup: %w", user.UnknownUserError("gone"))) {
		t.Error("unknown user not recognized")
	}
	if !isUserMissing(user.UnknownUserIdError(1001)) {
		t.Error("unknown UID not recognized")
	}
	err := &os.PathError{
		Op:   "open",
		Path: "/etc/passwd",
		Err:  os.ErrNotExist,
	}
	if isUserMissing(err) {
		t.Error("missing database classified as missing user")
	}
}

type graceTestConn struct {
	net.Conn
	closed chan struct{}
}

func (c *graceTestConn) Close() error {
	close(c.closed)
	return nil
}

func TestLoginGraceExtensionDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nc := &graceTestConn{closed: make(chan struct{})}
		c := &conn{srv: &server{logf: t.Logf}, netConn: nc}
		defer c.stopConnTimers()
		c.mu.Lock()
		c.armLoginGraceLocked(time.Second)
		c.mu.Unlock()
		c.extendLoginGrace(holdDelegateGrace)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		select {
		case <-nc.closed:
			t.Fatal("superseded grace timer closed the connection")
		default:
		}
		time.Sleep(holdDelegateGrace)
		synctest.Wait()
		select {
		case <-nc.closed:
		default:
			t.Fatal("extended grace timer did not close the connection")
		}
	})
}

// blockedAuthSigner pauses after the server accepts an unsigned key query.
type blockedAuthSigner struct {
	testssh.Signer
	entered chan struct{}
	release chan struct{}
}

func (s *blockedAuthSigner) Sign(io.Reader, []byte) (*testssh.Signature, error) {
	close(s.entered)
	<-s.release
	return nil, errors.New("test stopped before signing")
}

func TestLoginGraceIncompleteAuthentication(t *testing.T) {
	for _, method := range []string{"unsigned-key", "partial-password"} {
		t.Run(method, func(t *testing.T) {
			lu := sessionTestUser(t)
			p := &policyFlipper{
				localState: &localState{
					sshEnabled: true,
					varRoot:    t.TempDir(),
				},
				rule: newPolicyRule(&tailcfg.SSHAction{Accept: true}, lu),
			}
			srv, sc, done := startPolicyConn(t, p)
			entered, release := make(chan struct{}), make(chan struct{})
			cfg := &testssh.ClientConfig{
				User:            "alice",
				HostKeyCallback: testssh.InsecureIgnoreHostKey(),
			}
			if method == "unsigned-key" {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := testssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatal(err)
				}
				cfg.SkipNoneAuth = true
				cfg.Auth = []testssh.AuthMethod{
					testssh.PublicKeys(&blockedAuthSigner{
						Signer:  signer,
						entered: entered,
						release: release,
					}),
				}
			} else {
				cfg.User += forcePasswordSuffix
				password := testssh.PasswordCallback(func() (string, error) {
					close(entered)
					<-release
					return "", errors.New("test stopped before password")
				})
				cfg.Auth = []testssh.AuthMethod{password}
			}
			clientDone := make(chan struct{})
			addr := sc.RemoteAddr().String()
			go func() {
				defer close(clientDone)
				cl, _, _, _ := testssh.NewClientConn(sc, addr, cfg)
				if cl != nil {
					cl.Close()
				}
			}()
			defer func() {
				close(release)
				sc.Close()
				<-clientDone
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("authentication did not reach continuation")
			}
			srv.mu.Lock()
			var c *conn
			for c = range srv.activeConns {
			}
			srv.mu.Unlock()
			if c == nil {
				t.Fatal("connection disappeared before grace expiry")
			}
			c.mu.Lock()
			active := c.graceTimer != nil && !c.authCompleted.Load()
			if active {
				c.graceTimer.Reset(0)
			}
			c.mu.Unlock()
			if !active {
				t.Fatal("incomplete authentication disabled login grace")
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("grace expiry did not close the unfinished handshake")
			}
		})
	}
}
