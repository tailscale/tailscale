// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || darwin
// +build linux darwin

package tailssh

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"inet.af/netaddr"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/gliderlabs/ssh"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/lineread"
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
			name:    "nil-rule",
			rule:    nil,
			wantErr: errNilRule,
		},
		{
			name:    "nil-action",
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
			ci:       &sshConnInfo{src: netaddr.MustParseIPPort("1.2.3.4:30343")},
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
			ci:       &sshConnInfo{uprof: &tailcfg.UserProfile{LoginName: "foo@bar.com"}},
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
		src:     netaddr.MustParseIPPort("1.2.3.4:32342"),
		dst:     netaddr.MustParseIPPort("1.2.3.5:22"),
		node:    &tailcfg.Node{},
		uprof:   &tailcfg.UserProfile{},
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
			uprof: &tailcfg.UserProfile{
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
