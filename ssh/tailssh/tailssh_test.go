// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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

	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/memnet"
	"tailscale.com/net/tsdial"
	"tailscale.com/sessionrecording"
	"tailscale.com/tailcfg"
	"tailscale.com/tempfork/gliderlabs/ssh"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tsd"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logid"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/lineiter"
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
				srv:  &server{logf: tstest.WhileTestRunningLogger(t)},
			}
			got, gotUser, gotAcceptEnv, err := c.matchRule(tt.rule)
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
		wantResult    evalResult
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
			wantResult:    accepted,
		},
		{
			name: "no-matches-returns-rejected",
			policy: &tailcfg.SSHPolicy{
				Rules: []*tailcfg.SSHRule{},
			},
			ci:            &sshConnInfo{sshUser: "alice"},
			wantUser:      "",
			wantAcceptEnv: nil,
			wantResult:    rejected,
		},
		{
			name: "no-user-matches-returns-rejected-user",
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
			wantResult:    rejectedUser,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &conn{
				info: tt.ci,
				srv:  &server{logf: tstest.WhileTestRunningLogger(t)},
			}
			got, gotUser, gotAcceptEnv, result := c.evalSSHPolicy(tt.policy)
			if result != tt.wantResult {
				t.Errorf("result = %v; want %v", result, tt.wantResult)
			}
			if gotUser != tt.wantUser {
				t.Errorf("user = %q; want %q", gotUser, tt.wantUser)
			}
			if tt.wantResult == accepted && got == nil {
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
			"alice": currentUser,
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
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/7707")

	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; only runs on linux and darwin", runtime.GOOS)
	}

	var handler http.HandlerFunc
	recordingServer := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		handler(w, r)
	})

	s := &server{
		logf: tstest.WhileTestRunningLogger(t),
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
	cfg := &testssh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: testssh.InsecureIgnoreHostKey(),
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
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				r.Body.Read(make([]byte, 1))
				time.Sleep(100 * time.Millisecond)
			},
			sshCommand:       "echo hello && sleep 1 && echo world",
			wantClientOutput: "\r\n\r\nsession terminated\r\n\r\n",

			clientOutputMustNotContain: []string{"world"},
		},
	}

	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s.logf = tstest.WhileTestRunningLogger(t)
			tstest.Replace(t, &handler, tt.handler)
			sc, dc := memnet.NewTCPConn(src, dst, 1024)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
				if err != nil {
					t.Errorf("client: %v", err)
					return
				}
				client := testssh.NewClient(c, chans, reqs)
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
	recordingServer := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		io.ReadAll(r.Body)
	})
	badRecorder, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	badRecorderAddr := badRecorder.Addr().String()
	badRecorder.Close()

	badRecordingServer500 := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	s := &server{
		logf: tstest.WhileTestRunningLogger(t),
		lb: &localState{
			sshEnabled: true,
			matchingRule: newSSHRule(
				&tailcfg.SSHAction{
					Accept: true,
					Recorders: []netip.AddrPort{
						netip.MustParseAddrPort(badRecorderAddr),
						netip.MustParseAddrPort(badRecordingServer500.Listener.Addr().String()),
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
	cfg := &testssh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
		if err != nil {
			t.Errorf("client: %v", err)
			return
		}
		client := testssh.NewClient(c, chans, reqs)
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
	recordingServer := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		defer cancel()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		var err error
		recording, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
	})

	s := &server{
		logf: tstest.WhileTestRunningLogger(t),
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
	cfg := &testssh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
		if err != nil {
			t.Errorf("client: %v", err)
			return
		}
		client := testssh.NewClient(c, chans, reqs)
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
	bobRule := newSSHRule(&tailcfg.SSHAction{
		Accept:  true,
		Message: "Welcome to Tailscale SSH!",
	})
	bobRule.SSHUsers = map[string]string{"bob": "bob"}
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
			authErr:     true,
			wantBanners: []string{"tailscale: tailnet policy does not permit you to SSH to this node\n"},
		},
		{
			name: "user-mismatch",
			state: &localState{
				sshEnabled:   true,
				matchingRule: bobRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "alice"` + "\n"},
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
		logf: tstest.WhileTestRunningLogger(t),
	}
	defer s.Shutdown()
	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	for _, tc := range tests {
		for _, authMethods := range [][]string{nil, {"publickey", "password"}, {"password", "publickey"}} {
			t.Run(fmt.Sprintf("%s-skip-none-auth-%v", tc.name, strings.Join(authMethods, "-then-")), func(t *testing.T) {
				s.logf = tstest.WhileTestRunningLogger(t)

				sc, dc := memnet.NewTCPConn(src, dst, 1024)
				s.lb = tc.state
				sshUser := "alice"
				if tc.sshUser != "" {
					sshUser = tc.sshUser
				}

				wantBanners := slices.Clone(tc.wantBanners)
				noneAuthEnabled := len(authMethods) == 0

				var publicKeyUsed atomic.Bool
				var passwordUsed atomic.Bool
				var methods []testssh.AuthMethod

				for _, authMethod := range authMethods {
					switch authMethod {
					case "publickey":
						methods = append(methods,
							testssh.PublicKeysCallback(func() (signers []testssh.Signer, err error) {
								publicKeyUsed.Store(true)
								key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
								if err != nil {
									return nil, err
								}
								sig, err := testssh.NewSignerFromKey(key)
								if err != nil {
									return nil, err
								}
								return []testssh.Signer{sig}, nil
							}))
					case "password":
						methods = append(methods, testssh.PasswordCallback(func() (secret string, err error) {
							passwordUsed.Store(true)
							return "any-pass", nil
						}))
					}
				}

				if noneAuthEnabled && tc.usesPassword {
					methods = append(methods, testssh.PasswordCallback(func() (secret string, err error) {
						passwordUsed.Store(true)
						return "any-pass", nil
					}))
				}

				cfg := &testssh.ClientConfig{
					User:            sshUser,
					HostKeyCallback: testssh.InsecureIgnoreHostKey(),
					SkipNoneAuth:    !noneAuthEnabled,
					Auth:            methods,
					BannerCallback: func(message string) error {
						if len(wantBanners) == 0 {
							t.Errorf("unexpected banner: %q", message)
						} else if message != wantBanners[0] {
							t.Errorf("banner = %q; want %q", message, wantBanners[0])
						} else {
							t.Logf("banner = %q", message)
							wantBanners = wantBanners[1:]
						}
						return nil
					},
				}

				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
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
					client := testssh.NewClient(c, chans, reqs)
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
				if len(wantBanners) > 0 {
					t.Errorf("missing banners: %v", wantBanners)
				}

				// Check to see which callbacks were invoked.
				//
				// When `none` auth is enabled, the public key callback should
				// never fire, and the password callback should only fire if
				// authentication succeeded and the client was trying to force
				// password authentication by connecting with the '-password'
				// username suffix.
				//
				// When skipping `none` auth, the first callback should always
				// fire, and the 2nd callback should fire only if
				// authentication failed.
				wantPublicKey := false
				wantPassword := false
				if noneAuthEnabled {
					wantPassword = !tc.authErr && tc.usesPassword
				} else {
					for i, authMethod := range authMethods {
						switch authMethod {
						case "publickey":
							wantPublicKey = i == 0 || tc.authErr
						case "password":
							wantPassword = i == 0 || tc.authErr
						}
					}
				}

				if wantPublicKey && !publicKeyUsed.Load() {
					t.Error("public key should have been attempted")
				} else if !wantPublicKey && publicKeyUsed.Load() {
					t.Errorf("public key should not have been attempted")
				}

				if wantPassword && !passwordUsed.Load() {
					t.Error("password should have been attempted")
				} else if !wantPassword && passwordUsed.Load() {
					t.Error("password should not have been attempted")
				}
			})
		}
	}
}

func TestSSH(t *testing.T) {
	logf := tstest.WhileTestRunningLogger(t)
	sys := tsd.NewSystem()
	eng, err := wgengine.NewFakeUserspaceEngine(logf, sys.Set, sys.HealthTracker.Get(), sys.UserMetricsRegistry(), sys.Bus.Get())
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
	for line := range lineiter.Bytes(out) {
		if i := bytes.IndexByte(line, '='); i != -1 {
			e[string(line[:i])] = string(line[i+1:])
		}
	}
	return e
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

func mockRecordingServer(t *testing.T, handleRecord http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /record", func(http.ResponseWriter, *http.Request) {
		t.Errorf("v1 recording endpoint called")
	})
	mux.HandleFunc("HEAD /v2/record", func(http.ResponseWriter, *http.Request) {})
	mux.HandleFunc("POST /v2/record", handleRecord)

	h2s := &http2.Server{}
	srv := httptest.NewUnstartedServer(h2c.NewHandler(mux, h2s))
	if err := http2.ConfigureServer(srv.Config, h2s); err != nil {
		t.Errorf("configuring HTTP/2 support in recording server: %v", err)
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}
