// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || darwin

package tailssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/nettest"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/gliderlabs/ssh"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/lineread"
	"tailscale.com/util/must"
	"tailscale.com/util/strs"
	"tailscale.com/wgengine"
)

func TestMatchRule(t *testing.T) {
	someAction := new(tailcfg.SSHAction)
	tests := []struct {
		name     string
		rule     *tailcfg.SSHRule
		ci       *sshConnInfo
		wantErr  error
		wantUser string
	}{
		{
			name: "invalid-conn",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				SSHUsers: map[string]string{
					"*": "ubuntu",
				},
			},
			wantErr: errInvalidConn,
		},
		{
			name:    "nil-rule",
			ci:      &sshConnInfo{},
			rule:    nil,
			wantErr: errNilRule,
		},
		{
			name:    "nil-action",
			ci:      &sshConnInfo{},
			rule:    &tailcfg.SSHRule{},
			wantErr: errNilAction,
		},
		{
			name: "expired",
			rule: &tailcfg.SSHRule{
				Action:      someAction,
				RuleExpires: timePtr(time.Unix(100, 0)),
			},
			ci:      &sshConnInfo{},
			wantErr: errRuleExpired,
		},
		{
			name: "no-principal",
			rule: &tailcfg.SSHRule{
				Action: someAction,
				SSHUsers: map[string]string{
					"*": "ubuntu",
				}},
			ci:      &sshConnInfo{},
			wantErr: errPrincipalMatch,
		},
		{
			name: "no-user-match",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
			},
			ci:      &sshConnInfo{sshUser: "alice"},
			wantErr: errUserMatch,
		},
		{
			name: "ok-wildcard",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				SSHUsers: map[string]string{
					"*": "ubuntu",
				},
			},
			ci:       &sshConnInfo{sshUser: "alice"},
			wantUser: "ubuntu",
		},
		{
			name: "ok-wildcard-and-nil-principal",
			rule: &tailcfg.SSHRule{
				Action: someAction,
				Principals: []*tailcfg.SSHPrincipal{
					nil, // don't crash on this
					{Any: true},
				},
				SSHUsers: map[string]string{
					"*": "ubuntu",
				},
			},
			ci:       &sshConnInfo{sshUser: "alice"},
			wantUser: "ubuntu",
		},
		{
			name: "ok-exact",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				SSHUsers: map[string]string{
					"*":     "ubuntu",
					"alice": "thealice",
				},
			},
			ci:       &sshConnInfo{sshUser: "alice"},
			wantUser: "thealice",
		},
		{
			name: "no-users-for-reject",
			rule: &tailcfg.SSHRule{
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				Action:     &tailcfg.SSHAction{Reject: true},
			},
			ci: &sshConnInfo{sshUser: "alice"},
		},
		{
			name: "match-principal-node-ip",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{NodeIP: "1.2.3.4"}},
				SSHUsers:   map[string]string{"*": "ubuntu"},
			},
			ci:       &sshConnInfo{src: netip.MustParseAddrPort("1.2.3.4:30343")},
			wantUser: "ubuntu",
		},
		{
			name: "match-principal-node-id",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{Node: "some-node-ID"}},
				SSHUsers:   map[string]string{"*": "ubuntu"},
			},
			ci:       &sshConnInfo{node: &tailcfg.Node{StableID: "some-node-ID"}},
			wantUser: "ubuntu",
		},
		{
			name: "match-principal-userlogin",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{UserLogin: "foo@bar.com"}},
				SSHUsers:   map[string]string{"*": "ubuntu"},
			},
			ci:       &sshConnInfo{uprof: tailcfg.UserProfile{LoginName: "foo@bar.com"}},
			wantUser: "ubuntu",
		},
		{
			name: "ssh-user-equal",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				SSHUsers: map[string]string{
					"*": "=",
				},
			},
			ci:       &sshConnInfo{sshUser: "alice"},
			wantUser: "alice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &conn{
				info: tt.ci,
				srv:  &server{logf: t.Logf},
			}
			got, gotUser, err := c.matchRule(tt.rule, nil)
			if err != tt.wantErr {
				t.Errorf("err = %v; want %v", err, tt.wantErr)
			}
			if gotUser != tt.wantUser {
				t.Errorf("user = %q; want %q", gotUser, tt.wantUser)
			}
			if err == nil && got == nil {
				t.Errorf("expected non-nil action on success")
			}
		})
	}
}

func timePtr(t time.Time) *time.Time { return &t }

// localState implements ipnLocalBackend for testing.
type localState struct {
	sshEnabled   bool
	matchingRule *tailcfg.SSHRule

	// serverActions is a map of the action name to the action.
	// It is served for paths like https://unused/ssh-action/<action-name>.
	// The action name is the last part of the action URL.
	serverActions map[string]*tailcfg.SSHAction
}

var (
	currentUser    = os.Getenv("USER") // Use the current user for the test.
	testSigner     gossh.Signer
	testSignerOnce sync.Once
)

func (ts *localState) GetSSH_HostKeys() ([]gossh.Signer, error) {
	testSignerOnce.Do(func() {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
		s, err := gossh.NewSignerFromSigner(priv)
		if err != nil {
			panic(err)
		}
		testSigner = s
	})
	return []gossh.Signer{testSigner}, nil
}

func (ts *localState) ShouldRunSSH() bool {
	return ts.sshEnabled
}

func (ts *localState) NetMap() *netmap.NetworkMap {
	var policy *tailcfg.SSHPolicy
	if ts.matchingRule != nil {
		policy = &tailcfg.SSHPolicy{
			Rules: []*tailcfg.SSHRule{
				ts.matchingRule,
			},
		}
	}

	return &netmap.NetworkMap{
		SelfNode: &tailcfg.Node{
			ID: 1,
		},
		SSHPolicy: policy,
	}
}

func (ts *localState) WhoIs(ipp netip.AddrPort) (n *tailcfg.Node, u tailcfg.UserProfile, ok bool) {
	return &tailcfg.Node{
			ID:       2,
			StableID: "peer-id",
		}, tailcfg.UserProfile{
			LoginName: "peer",
		}, true

}

func (ts *localState) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	k, ok := strs.CutPrefix(req.URL.Path, "/ssh-action/")
	if !ok {
		rec.WriteHeader(http.StatusNotFound)
	}
	a, ok := ts.serverActions[k]
	if !ok {
		rec.WriteHeader(http.StatusNotFound)
		return rec.Result(), nil
	}
	rec.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(rec).Encode(a); err != nil {
		return nil, err
	}
	return rec.Result(), nil
}

func (ts *localState) TailscaleVarRoot() string {
	return ""
}

func newSSHRule(action *tailcfg.SSHAction) *tailcfg.SSHRule {
	return &tailcfg.SSHRule{
		SSHUsers: map[string]string{
			"*": currentUser,
		},
		Action: action,
		Principals: []*tailcfg.SSHPrincipal{
			{
				Any: true,
			},
		},
	}
}

func TestSSHAuthFlow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Not running on Linux, skipping")
	}
	acceptRule := newSSHRule(&tailcfg.SSHAction{
		Accept:  true,
		Message: "Welcome to Tailscale SSH!",
	})
	rejectRule := newSSHRule(&tailcfg.SSHAction{
		Reject:  true,
		Message: "Go Away!",
	})

	tests := []struct {
		name         string
		sshUser      string // defaults to alice
		state        *localState
		wantBanners  []string
		usesPassword bool
		authErr      bool
	}{
		{
			name: "no-policy",
			state: &localState{
				sshEnabled: true,
			},
			authErr: true,
		},
		{
			name: "accept",
			state: &localState{
				sshEnabled:   true,
				matchingRule: acceptRule,
			},
			wantBanners: []string{"Welcome to Tailscale SSH!"},
		},
		{
			name: "reject",
			state: &localState{
				sshEnabled:   true,
				matchingRule: rejectRule,
			},
			wantBanners: []string{"Go Away!"},
			authErr:     true,
		},
		{
			name: "simple-check",
			state: &localState{
				sshEnabled: true,
				matchingRule: newSSHRule(&tailcfg.SSHAction{
					HoldAndDelegate: "https://unused/ssh-action/accept",
				}),
				serverActions: map[string]*tailcfg.SSHAction{
					"accept": acceptRule.Action,
				},
			},
			wantBanners: []string{"Welcome to Tailscale SSH!"},
		},
		{
			name: "multi-check",
			state: &localState{
				sshEnabled: true,
				matchingRule: newSSHRule(&tailcfg.SSHAction{
					Message:         "First",
					HoldAndDelegate: "https://unused/ssh-action/check1",
				}),
				serverActions: map[string]*tailcfg.SSHAction{
					"check1": {
						Message:         "url-here",
						HoldAndDelegate: "https://unused/ssh-action/check2",
					},
					"check2": acceptRule.Action,
				},
			},
			wantBanners: []string{"First", "url-here", "Welcome to Tailscale SSH!"},
		},
		{
			name: "check-reject",
			state: &localState{
				sshEnabled: true,
				matchingRule: newSSHRule(&tailcfg.SSHAction{
					Message:         "First",
					HoldAndDelegate: "https://unused/ssh-action/reject",
				}),
				serverActions: map[string]*tailcfg.SSHAction{
					"reject": rejectRule.Action,
				},
			},
			wantBanners: []string{"First", "Go Away!"},
			authErr:     true,
		},
		{
			name:    "force-password-auth",
			sshUser: "alice+password",
			state: &localState{
				sshEnabled:   true,
				matchingRule: acceptRule,
			},
			usesPassword: true,
			wantBanners:  []string{"Welcome to Tailscale SSH!"},
		},
	}
	s := &server{
		logf: logger.Discard,
	}
	defer s.Shutdown()
	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sc, dc := nettest.NewTCPConn(src, dst, 1024)
			s.lb = tc.state
			sshUser := "alice"
			if tc.sshUser != "" {
				sshUser = tc.sshUser
			}
			var passwordUsed atomic.Bool
			cfg := &gossh.ClientConfig{
				User:            sshUser,
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
				Auth: []gossh.AuthMethod{
					gossh.PasswordCallback(func() (secret string, err error) {
						if !tc.usesPassword {
							t.Error("unexpected use of PasswordCallback")
							return "", errors.New("unexpected use of PasswordCallback")
						}
						passwordUsed.Store(true)
						return "any-pass", nil
					}),
				},
				BannerCallback: func(message string) error {
					if len(tc.wantBanners) == 0 {
						t.Errorf("unexpected banner: %q", message)
					} else if message != tc.wantBanners[0] {
						t.Errorf("banner = %q; want %q", message, tc.wantBanners[0])
					} else {
						t.Logf("banner = %q", message)
						tc.wantBanners = tc.wantBanners[1:]
					}
					return nil
				},
			}
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, chans, reqs, err := gossh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
				if err != nil {
					if !tc.authErr {
						t.Errorf("client: %v", err)
					}
					return
				} else if tc.authErr {
					c.Close()
					t.Errorf("client: expected error, got nil")
					return
				}
				client := gossh.NewClient(c, chans, reqs)
				defer client.Close()
				session, err := client.NewSession()
				if err != nil {
					t.Errorf("client: %v", err)
					return
				}
				defer session.Close()
				_, err = session.CombinedOutput("echo Ran echo!")
				if err != nil {
					t.Errorf("client: %v", err)
				}
			}()
			if err := s.HandleSSHConn(dc); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			wg.Wait()
			if len(tc.wantBanners) > 0 {
				t.Errorf("missing banners: %v", tc.wantBanners)
			}
		})
	}
}

func TestSSH(t *testing.T) {
	var logf logger.Logf = t.Logf
	eng, err := wgengine.NewFakeUserspaceEngine(logf, 0)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := ipnlocal.NewLocalBackend(logf, "",
		new(mem.Store),
		new(tsdial.Dialer),
		eng, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lb.Shutdown()
	dir := t.TempDir()
	lb.SetVarRoot(dir)

	srv := &server{
		lb:   lb,
		logf: logf,
	}
	sc, err := srv.newConn()
	if err != nil {
		t.Fatal(err)
	}
	// Remove the auth checks for the test
	sc.insecureSkipTailscaleAuth = true

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	sc.localUser = u
	sc.info = &sshConnInfo{
		sshUser: "test",
		src:     netip.MustParseAddrPort("1.2.3.4:32342"),
		dst:     netip.MustParseAddrPort("1.2.3.5:22"),
		node:    &tailcfg.Node{},
		uprof:   tailcfg.UserProfile{},
	}
	sc.finalAction = &tailcfg.SSHAction{Accept: true}

	sc.Handler = func(s ssh.Session) {
		sc.newSSHSession(s).run()
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("Accept: %v", err)
				}
				return
			}
			go sc.HandleConn(c)
		}
	}()

	execSSH := func(args ...string) *exec.Cmd {
		cmd := exec.Command("ssh",
			"-F",
			"none",
			"-v",
			"-p", fmt.Sprint(port),
			"-o", "StrictHostKeyChecking=no",
			"user@127.0.0.1")
		cmd.Args = append(cmd.Args, args...)
		return cmd
	}

	t.Run("env", func(t *testing.T) {
		if cibuild.On() {
			t.Skip("Skipping for now; see https://github.com/tailscale/tailscale/issues/4051")
		}
		cmd := execSSH("LANG=foo env")
		cmd.Env = append(os.Environ(), "LOCAL_ENV=bar")
		got, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal(err, string(got))
		}
		m := parseEnv(got)
		if got := m["USER"]; got == "" || got != u.Username {
			t.Errorf("USER = %q; want %q", got, u.Username)
		}
		if got := m["HOME"]; got == "" || got != u.HomeDir {
			t.Errorf("HOME = %q; want %q", got, u.HomeDir)
		}
		if got := m["PWD"]; got == "" || got != u.HomeDir {
			t.Errorf("PWD = %q; want %q", got, u.HomeDir)
		}
		if got := m["SHELL"]; got == "" {
			t.Errorf("no SHELL")
		}
		if got, want := m["LANG"], "foo"; got != want {
			t.Errorf("LANG = %q; want %q", got, want)
		}
		if got := m["LOCAL_ENV"]; got != "" {
			t.Errorf("LOCAL_ENV leaked over ssh: %v", got)
		}
		t.Logf("got: %+v", m)
	})

	t.Run("stdout_stderr", func(t *testing.T) {
		cmd := execSSH("sh", "-c", "echo foo; echo bar >&2")
		var outBuf, errBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		t.Logf("Got: %q and %q", outBuf.Bytes(), errBuf.Bytes())
		// TODO: figure out why these aren't right. should be
		// "foo\n" and "bar\n", not "\n" and "bar\n".
	})

	t.Run("stdin", func(t *testing.T) {
		if cibuild.On() {
			t.Skip("Skipping for now; see https://github.com/tailscale/tailscale/issues/4051")
		}
		cmd := execSSH("cat")
		var outBuf bytes.Buffer
		cmd.Stdout = &outBuf
		const str = "foo\nbar\n"
		cmd.Stdin = strings.NewReader(str)
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		if got := outBuf.String(); got != str {
			t.Errorf("got %q; want %q", got, str)
		}
	})
}

func parseEnv(out []byte) map[string]string {
	e := map[string]string{}
	lineread.Reader(bytes.NewReader(out), func(line []byte) error {
		i := bytes.IndexByte(line, '=')
		if i == -1 {
			return nil
		}
		e[string(line[:i])] = string(line[i+1:])
		return nil
	})
	return e
}

func TestPublicKeyFetching(t *testing.T) {
	var reqsTotal, reqsIfNoneMatchHit, reqsIfNoneMatchMiss int32
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32((&reqsTotal), 1)
		etag := fmt.Sprintf("W/%q", sha256.Sum256([]byte(r.URL.Path)))
		w.Header().Set("Etag", etag)
		if v := r.Header.Get("If-None-Match"); v != "" {
			if v == etag {
				atomic.AddInt32(&reqsIfNoneMatchHit, 1)
				w.WriteHeader(304)
				return
			}
			atomic.AddInt32(&reqsIfNoneMatchMiss, 1)
		}
		io.WriteString(w, "foo\nbar\n"+string(r.URL.Path)+"\n")
	}))
	ts.StartTLS()
	defer ts.Close()
	keys := ts.URL

	clock := &tstest.Clock{}
	srv := &server{
		pubKeyHTTPClient: ts.Client(),
		timeNow:          clock.Now,
	}
	for i := 0; i < 2; i++ {
		got, err := srv.fetchPublicKeysURL(keys + "/alice.keys")
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"foo", "bar", "/alice.keys"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %q; want %q", got, want)
		}
	}
	if got, want := atomic.LoadInt32(&reqsTotal), int32(1); got != want {
		t.Errorf("got %d requests; want %d", got, want)
	}
	if got, want := atomic.LoadInt32(&reqsIfNoneMatchHit), int32(0); got != want {
		t.Errorf("got %d etag hits; want %d", got, want)
	}
	clock.Advance(5 * time.Minute)
	got, err := srv.fetchPublicKeysURL(keys + "/alice.keys")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"foo", "bar", "/alice.keys"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
	if got, want := atomic.LoadInt32(&reqsTotal), int32(2); got != want {
		t.Errorf("got %d requests; want %d", got, want)
	}
	if got, want := atomic.LoadInt32(&reqsIfNoneMatchHit), int32(1); got != want {
		t.Errorf("got %d etag hits; want %d", got, want)
	}
	if got, want := atomic.LoadInt32(&reqsIfNoneMatchMiss), int32(0); got != want {
		t.Errorf("got %d etag misses; want %d", got, want)
	}

}

func TestExpandPublicKeyURL(t *testing.T) {
	c := &conn{
		info: &sshConnInfo{
			uprof: tailcfg.UserProfile{
				LoginName: "bar@baz.tld",
			},
		},
	}
	if got, want := c.expandPublicKeyURL("foo"), "foo"; got != want {
		t.Errorf("basic: got %q; want %q", got, want)
	}
	if got, want := c.expandPublicKeyURL("https://example.com/$LOGINNAME_LOCALPART.keys"), "https://example.com/bar.keys"; got != want {
		t.Errorf("localpart: got %q; want %q", got, want)
	}
	if got, want := c.expandPublicKeyURL("https://example.com/keys?email=$LOGINNAME_EMAIL"), "https://example.com/keys?email=bar@baz.tld"; got != want {
		t.Errorf("email: got %q; want %q", got, want)
	}
	c.info = new(sshConnInfo)
	if got, want := c.expandPublicKeyURL("https://example.com/keys?email=$LOGINNAME_EMAIL"), "https://example.com/keys?email="; got != want {
		t.Errorf("on empty: got %q; want %q", got, want)
	}
}

func TestAcceptEnvPair(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"TERM=x", true},
		{"term=x", false},
		{"TERM", false},
		{"LC_FOO=x", true},
		{"LD_PRELOAD=naah", false},
		{"TERM=screen-256color", true},
	}
	for _, tt := range tests {
		if got := acceptEnvPair(tt.in); got != tt.want {
			t.Errorf("for %q, got %v; want %v", tt.in, got, tt.want)
		}
	}
}
