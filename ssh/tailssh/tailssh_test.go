// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"bytes"
	"context"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gossh "github.com/tailscale/golang-x-crypto/ssh"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/memnet"
	"tailscale.com/net/tsdial"
	"tailscale.com/sessionrecording"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/gliderlabs/ssh"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/lineread"
	"tailscale.com/util/must"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
)

func TestMatchRule(t *testing.T) {
	someAction := new(tailcfg.SSHAction)
	tests := []struct {
		name          string
		rule          *tailcfg.SSHRule
		ci            *sshConnInfo
		wantErr       error
		wantUser      string
		wantAcceptEnv []string
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
				RuleExpires: ptr.To(time.Unix(100, 0)),
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
			name: "ok-with-accept-env",
			rule: &tailcfg.SSHRule{
				Action:     someAction,
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				SSHUsers: map[string]string{
					"*":     "ubuntu",
					"alice": "thealice",
				},
				AcceptEnv: []string{"EXAMPLE", "?_?", "TEST_*"},
			},
			ci:            &sshConnInfo{sshUser: "alice"},
			wantUser:      "thealice",
			wantAcceptEnv: []string{"EXAMPLE", "?_?", "TEST_*"},
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
			ci:       &sshConnInfo{node: (&tailcfg.Node{StableID: "some-node-ID"}).View()},
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
			got, gotUser, gotAcceptEnv, err := c.matchRule(tt.rule, nil)
			if err != tt.wantErr {
				t.Errorf("err = %v; want %v", err, tt.wantErr)
			}
			if gotUser != tt.wantUser {
				t.Errorf("user = %q; want %q", gotUser, tt.wantUser)
			}
			if err == nil && got == nil {
				t.Errorf("expected non-nil action on success")
			}
			if !slices.Equal(gotAcceptEnv, tt.wantAcceptEnv) {
				t.Errorf("acceptEnv = %v; want %v", gotAcceptEnv, tt.wantAcceptEnv)
			}
		})
	}
}

func TestEvalSSHPolicy(t *testing.T) {
	someAction := new(tailcfg.SSHAction)
	tests := []struct {
		name          string
		policy        *tailcfg.SSHPolicy
		ci            *sshConnInfo
		wantMatch     bool
		wantUser      string
		wantAcceptEnv []string
	}{
		{
			name: "multiple-matches-picks-first-match",
			policy: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"other": "other1",
						},
					},
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"*":     "ubuntu",
							"alice": "thealice",
						},
						AcceptEnv: []string{"EXAMPLE", "?_?", "TEST_*"},
					},
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"other2": "other3",
						},
					},
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"*":     "ubuntu",
							"alice": "thealice",
							"mark":  "markthe",
						},
						AcceptEnv: []string{"*"},
					},
				},
			},
			ci:            &sshConnInfo{sshUser: "alice"},
			wantUser:      "thealice",
			wantAcceptEnv: []string{"EXAMPLE", "?_?", "TEST_*"},
			wantMatch:     true,
		},
		{
			name: "no-matches-returns-failure",
			policy: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"other": "other1",
						},
					},
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"fedora": "ubuntu",
						},
						AcceptEnv: []string{"EXAMPLE", "?_?", "TEST_*"},
					},
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"other2": "other3",
						},
					},
					{
						Action:     someAction,
						Principals: []*tailcfg.SSHPrincipal{{Any: true}},
						SSHUsers: map[string]string{
							"mark": "markthe",
						},
						AcceptEnv: []string{"*"},
					},
				},
			},
			ci:            &sshConnInfo{sshUser: "alice"},
			wantUser:      "",
			wantAcceptEnv: nil,
			wantMatch:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &conn{
				info: tt.ci,
				srv:  &server{logf: t.Logf},
			}
			got, gotUser, gotAcceptEnv, match := c.evalSSHPolicy(tt.policy, nil)
			if match != tt.wantMatch {
				t.Errorf("match = %v; want %v", match, tt.wantMatch)
			}
			if gotUser != tt.wantUser {
				t.Errorf("user = %q; want %q", gotUser, tt.wantUser)
			}
			if tt.wantMatch == true && got == nil {
				t.Errorf("expected non-nil action on success")
			}
			if !slices.Equal(gotAcceptEnv, tt.wantAcceptEnv) {
				t.Errorf("acceptEnv = %v; want %v", gotAcceptEnv, tt.wantAcceptEnv)
			}
		})
	}
}

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

func (ts *localState) Dialer() *tsdial.Dialer {
	return &tsdial.Dialer{}
}

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
		SelfNode: (&tailcfg.Node{
			ID: 1,
		}).View(),
		SSHPolicy: policy,
	}
}

func (ts *localState) WhoIs(proto string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	if proto != "tcp" {
		return tailcfg.NodeView{}, tailcfg.UserProfile{}, false
	}

	return (&tailcfg.Node{
			ID:       2,
			StableID: "peer-id",
		}).View(), tailcfg.UserProfile{
			LoginName: "peer",
		}, true

}

func (ts *localState) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	k, ok := strings.CutPrefix(req.URL.Path, "/ssh-action/")
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

func (ts *localState) NodeKey() key.NodePublic {
	return key.NewNode().Public()
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

func TestSSHRecordingCancelsSessionsOnUploadFailure(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; only runs on linux and darwin", runtime.GOOS)
	}

	var handler http.HandlerFunc
	recordingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	}))
	defer recordingServer.Close()

	s := &server{
		logf: t.Logf,
		lb: &localState{
			sshEnabled: true,
			matchingRule: newSSHRule(
				&tailcfg.SSHAction{
					Accept: true,
					Recorders: []netip.AddrPort{
						netip.MustParseAddrPort(recordingServer.Listener.Addr().String()),
					},
					OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
						RejectSessionWithMessage:    "session rejected",
						TerminateSessionWithMessage: "session terminated",
					},
				},
			),
		},
	}
	defer s.Shutdown()

	const sshUser = "alice"
	cfg := &gossh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	tests := []struct {
		name             string
		handler          func(w http.ResponseWriter, r *http.Request)
		sshCommand       string
		wantClientOutput string

		clientOutputMustNotContain []string
	}{
		{
			name: "upload-denied",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			sshCommand:       "echo hello",
			wantClientOutput: "session rejected\r\n",

			clientOutputMustNotContain: []string{"hello"},
		},
		{
			name: "upload-fails-after-starting",
			handler: func(w http.ResponseWriter, r *http.Request) {
				r.Body.Read(make([]byte, 1))
				time.Sleep(100 * time.Millisecond)
				w.WriteHeader(http.StatusInternalServerError)
			},
			sshCommand:       "echo hello && sleep 1 && echo world",
			wantClientOutput: "\r\n\r\nsession terminated\r\n\r\n",

			clientOutputMustNotContain: []string{"world"},
		},
	}

	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tstest.Replace(t, &handler, tt.handler)
			sc, dc := memnet.NewTCPConn(src, dst, 1024)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, chans, reqs, err := gossh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
				if err != nil {
					t.Errorf("client: %v", err)
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
				t.Logf("client established session")
				got, err := session.CombinedOutput(tt.sshCommand)
				if err != nil {
					t.Logf("client got: %q: %v", got, err)
				} else {
					t.Errorf("client did not get kicked out: %q", got)
				}
				gotStr := string(got)
				if !strings.HasSuffix(gotStr, tt.wantClientOutput) {
					t.Errorf("client got %q, want %q", got, tt.wantClientOutput)
				}
				for _, x := range tt.clientOutputMustNotContain {
					if strings.Contains(gotStr, x) {
						t.Errorf("client output must not contain %q", x)
					}
				}
			}()
			if err := s.HandleSSHConn(dc); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			wg.Wait()
		})
	}
}

func TestMultipleRecorders(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; only runs on linux and darwin", runtime.GOOS)
	}
	done := make(chan struct{})
	recordingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer recordingServer.Close()
	badRecorder, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	badRecorderAddr := badRecorder.Addr().String()
	badRecorder.Close()

	badRecordingServer500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer badRecordingServer500.Close()

	badRecordingServer200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer badRecordingServer200.Close()

	s := &server{
		logf: t.Logf,
		lb: &localState{
			sshEnabled: true,
			matchingRule: newSSHRule(
				&tailcfg.SSHAction{
					Accept: true,
					Recorders: []netip.AddrPort{
						netip.MustParseAddrPort(badRecorderAddr),
						netip.MustParseAddrPort(badRecordingServer500.Listener.Addr().String()),
						netip.MustParseAddrPort(badRecordingServer200.Listener.Addr().String()),
						netip.MustParseAddrPort(recordingServer.Listener.Addr().String()),
					},
					OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
						RejectSessionWithMessage:    "session rejected",
						TerminateSessionWithMessage: "session terminated",
					},
				},
			),
		},
	}
	defer s.Shutdown()

	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	sc, dc := memnet.NewTCPConn(src, dst, 1024)

	const sshUser = "alice"
	cfg := &gossh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, chans, reqs, err := gossh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
		if err != nil {
			t.Errorf("client: %v", err)
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
		t.Logf("client established session")
		out, err := session.CombinedOutput("echo Ran echo!")
		if err != nil {
			t.Errorf("client: %v", err)
		}
		if string(out) != "Ran echo!\n" {
			t.Errorf("client: unexpected output: %q", out)
		}
	}()
	if err := s.HandleSSHConn(dc); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	wg.Wait()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for recording")
	}
}

// TestSSHRecordingNonInteractive tests that the SSH server records the SSH session
// when the client is not interactive (i.e. no PTY).
// It starts a local SSH server and a recording server. The recording server
// records the SSH session and returns it to the test.
// The test then verifies that the recording has a valid CastHeader, it does not
// validate the contents of the recording.
func TestSSHRecordingNonInteractive(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; only runs on linux and darwin", runtime.GOOS)
	}
	var recording []byte
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	recordingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer cancel()
		var err error
		recording, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
	}))
	defer recordingServer.Close()

	s := &server{
		logf: logger.Discard,
		lb: &localState{
			sshEnabled: true,
			matchingRule: newSSHRule(
				&tailcfg.SSHAction{
					Accept: true,
					Recorders: []netip.AddrPort{
						must.Get(netip.ParseAddrPort(recordingServer.Listener.Addr().String())),
					},
					OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
						RejectSessionWithMessage:    "session rejected",
						TerminateSessionWithMessage: "session terminated",
					},
				},
			),
		},
	}
	defer s.Shutdown()

	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	sc, dc := memnet.NewTCPConn(src, dst, 1024)

	const sshUser = "alice"
	cfg := &gossh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, chans, reqs, err := gossh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
		if err != nil {
			t.Errorf("client: %v", err)
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
		t.Logf("client established session")
		_, err = session.CombinedOutput("echo Ran echo!")
		if err != nil {
			t.Errorf("client: %v", err)
		}
	}()
	if err := s.HandleSSHConn(dc); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	wg.Wait()

	<-ctx.Done() // wait for recording to finish
	var ch sessionrecording.CastHeader
	if err := json.NewDecoder(bytes.NewReader(recording)).Decode(&ch); err != nil {
		t.Fatal(err)
	}
	if ch.SSHUser != sshUser {
		t.Errorf("SSHUser = %q; want %q", ch.SSHUser, sshUser)
	}
	if ch.Command != "echo Ran echo!" {
		t.Errorf("Command = %q; want %q", ch.Command, "echo Ran echo!")
	}
}

func TestSSHAuthFlow(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; only runs on linux and darwin", runtime.GOOS)
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
			sc, dc := memnet.NewTCPConn(src, dst, 1024)
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
	sys := &tsd.System{}
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker(), sys.UserMetricsRegistry())
	if err != nil {
		t.Fatal(err)
	}
	sys.Set(eng)
	sys.Set(new(mem.Store))
	lb, err := ipnlocal.NewLocalBackend(logf, logid.PublicID{}, sys, 0)
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
	um, err := userLookup(u.Username)
	if err != nil {
		t.Fatal(err)
	}
	sc.localUser = um
	sc.info = &sshConnInfo{
		sshUser: "test",
		src:     netip.MustParseAddrPort("1.2.3.4:32342"),
		dst:     netip.MustParseAddrPort("1.2.3.5:22"),
		node:    (&tailcfg.Node{}).View(),
		uprof:   tailcfg.UserProfile{},
	}
	sc.action0 = &tailcfg.SSHAction{Accept: true}
	sc.finalAction = sc.action0

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

	t.Run("large_file", func(t *testing.T) {
		const wantSize = 1e6
		var outBuf bytes.Buffer
		cmd := execSSH("head", "-c", strconv.Itoa(wantSize), "/dev/zero")
		cmd.Stdout = &outBuf
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		if gotSize := outBuf.Len(); gotSize != wantSize {
			t.Fatalf("got %d, want %d", gotSize, int(wantSize))
		}
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
	for range 2 {
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

func TestPathFromPAMEnvLine(t *testing.T) {
	u := &user.User{Username: "foo", HomeDir: "/Homes/Foo"}
	tests := []struct {
		line string
		u    *user.User
		want string
	}{
		{"", u, ""},
		{`PATH   DEFAULT="/run/wrappers/bin:@{HOME}/.nix-profile/bin:/etc/profiles/per-user/@{PAM_USER}/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"`,
			u, "/run/wrappers/bin:/Homes/Foo/.nix-profile/bin:/etc/profiles/per-user/foo/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"},
		{`PATH   DEFAULT="@{SOMETHING_ELSE}:nope:@{HOME}"`,
			u, ""},
	}
	for i, tt := range tests {
		got := pathFromPAMEnvLine([]byte(tt.line), tt.u)
		if got != tt.want {
			t.Errorf("%d. got %q; want %q", i, got, tt.want)
		}
	}
}

func TestExpandDefaultPathTmpl(t *testing.T) {
	u := &user.User{Username: "foo", HomeDir: "/Homes/Foo"}
	tests := []struct {
		t    string
		u    *user.User
		want string
	}{
		{"", u, ""},
		{`/run/wrappers/bin:@{HOME}/.nix-profile/bin:/etc/profiles/per-user/@{PAM_USER}/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin`,
			u, "/run/wrappers/bin:/Homes/Foo/.nix-profile/bin:/etc/profiles/per-user/foo/bin:/nix/var/nix/profiles/default/bin:/run/current-system/sw/bin"},
		{`@{SOMETHING_ELSE}:nope:@{HOME}`, u, ""},
	}
	for i, tt := range tests {
		got := expandDefaultPathTmpl(tt.t, tt.u)
		if got != tt.want {
			t.Errorf("%d. got %q; want %q", i, got, tt.want)
		}
	}
}

func TestPathFromPAMEnvLineOnNixOS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping on non-linux")
	}
	if distro.Get() != distro.NixOS {
		t.Skip("skipping on non-NixOS")
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	got := defaultPathForUserOnNixOS(u)
	if got == "" {
		x, err := os.ReadFile("/etc/pam/environment")
		t.Fatalf("no result. file was: err=%v, contents=%s", err, x)
	}
	t.Logf("success; got=%q", got)
}

func TestStdOsUserUserAssumptions(t *testing.T) {
	v := reflect.TypeFor[user.User]()
	if got, want := v.NumField(), 5; got != want {
		t.Errorf("os/user.User has %v fields; this package assumes %v", got, want)
	}
}
