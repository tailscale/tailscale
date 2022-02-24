// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || darwin
// +build linux darwin

package tailssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"os/user"
	"testing"
	"time"

	"github.com/gliderlabs/ssh"
	"inet.af/netaddr"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
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
			ci:      &sshConnInfo{now: time.Unix(200, 0)},
			wantErr: errRuleExpired,
		},
		{
			name: "no-principal",
			rule: &tailcfg.SSHRule{
				Action: someAction,
			},
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
			ci:       &sshConnInfo{srcIP: netaddr.MustParseIP("1.2.3.4")},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotUser, err := matchRule(tt.rule, tt.ci)
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
	ml := new(tstest.MemLogger)
	var logf logger.Logf = ml.Logf
	eng, err := wgengine.NewFakeUserspaceEngine(logf, 0)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := ipnlocal.NewLocalBackend(logf, "",
		new(ipn.MemoryStore),
		new(tsdial.Dialer),
		eng, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lb.Shutdown()
	dir := t.TempDir()
	lb.SetVarRoot(dir)

	srv := &server{lb, logf}
	ss, err := srv.newSSHServer()
	if err != nil {
		t.Fatal(err)
	}

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	ci := &sshConnInfo{
		sshUser: "test",
		srcIP:   netaddr.MustParseIP("1.2.3.4"),
		node:    &tailcfg.Node{},
		uprof:   &tailcfg.UserProfile{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.Handler = func(s ssh.Session) {
		srv.handleAcceptedSSH(ctx, s, ci, u)
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
			go ss.HandleConn(c)
		}
	}()

	got, err := exec.Command("ssh",
		"-p", fmt.Sprint(port),
		"-o", "StrictHostKeyChecking=no",
		"user@127.0.0.1", "env").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %s", got)
}
