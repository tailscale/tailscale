// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/user"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"tailscale.com/cmd/testwrapper/flakytest"
	"tailscale.com/net/memnet"
	"tailscale.com/sessionrecording"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
	"tailscale.com/util/cibuild"
	"tailscale.com/util/lineiter"
	"tailscale.com/util/must"
	"tailscale.com/version/distro"
)

func TestMatchRule(t *testing.T) {
	someAction := new(tailcfg.SSHAction)
	// nonRootUser is a real non-root user in the local passwd database,
	// used by the "ssh-user-equal" case because mapLocalUser now does a
	// userLookup (via getent) when the mapped value is "=" and rejects root.
	nonRootUser := aNonRootUser(t)
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
				RuleExpires: new(time.Unix(100, 0)),
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
			ci:       &sshConnInfo{sshUser: nonRootUser},
			wantUser: nonRootUser,
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
			got, gotUser, gotAcceptEnv, _, result := c.evalSSHPolicy(tt.policy)
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

var currentUser = func() string {
	// Prefer user.Current because the USER env var is not set in
	// some environments (e.g. the golang:latest container used by CI).
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return os.Getenv("USER")
}()

// aNonRootUser returns the username of a non-root user that exists in the
// local passwd database (verified via userLookup, which uses getent on
// Linux). It prefers the current user, falling back to reading /etc/passwd
// for a real non-root account when the tests are run as root (e.g. in CI).
// It skips the test if no such user can be found.
func aNonRootUser(t *testing.T) string {
	t.Helper()
	if u, err := userLookup(currentUser); err == nil && u.Uid != "0" && u.Username != "root" {
		return currentUser
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		t.Skipf("can't find a non-root user: %v", err)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		fields := strings.Split(scan.Text(), ":")
		if len(fields) < 3 {
			continue
		}
		name, uid := fields[0], fields[2]
		if uid == "0" || name == "root" {
			continue
		}
		if _, err := userLookup(name); err == nil {
			return name
		}
	}
	t.Skip("can't find a non-root user in /etc/passwd")
	return ""
}

func newSSHRule(action *tailcfg.SSHAction) *tailcfg.SSHRule {
	return &tailcfg.SSHRule{
		SSHUsers: map[string]string{
			"alice": currentUser,
			"*":     "=",
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
	if runtime.GOOS == "darwin" {
		flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/7707")
	}
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
			varRoot:    t.TempDir(),
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
		wantExitCode     int // SSH exit status; 0 = don't check. 254 = recording infra failure.

		clientOutputMustNotContain []string
	}{
		{
			name: "upload-denied",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			sshCommand:       "echo hello",
			wantClientOutput: "session rejected\r\n",
			wantExitCode:     254,

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
			wg.Go(func() {
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
				if tt.wantExitCode != 0 {
					var exitErr *testssh.ExitError
					if errors.As(err, &exitErr) {
						if got := exitErr.ExitStatus(); got != tt.wantExitCode {
							t.Errorf("exit code = %d, want %d", got, tt.wantExitCode)
						}
					} else {
						t.Errorf("want *ssh.ExitError, got %T: %v", err, err)
					}
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
			})
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
			varRoot:    t.TempDir(),
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
	wg.Go(func() {
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
	})
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
	recordings := make(chan []byte, 2)
	recordingServer := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()

		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		recordings <- b
	})

	s := &server{
		logf: tstest.WhileTestRunningLogger(t),
		lb: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
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

	const sshUser = "alice"
	cfg := &testssh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	}

	var wg sync.WaitGroup
	runSession := func(command string) {
		sc, dc := memnet.NewTCPConn(src, dst, 1024)
		wg.Go(func() {
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
			// A non-zero exit (e.g. the shell rejecting an unbalanced
			// quote below) is fine here; we only care about the recording.
			if _, err := session.CombinedOutput(command); err != nil {
				t.Logf("client: %v", err)
			}
		})
		if err := s.HandleSSHConn(dc); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		wg.Wait()
	}

	// The first command records normally; the second has an unbalanced
	// single quote, which the shell lexer drops when reconstructing the
	// command. The CastHeader must record the raw client-provided command
	// either way, since that's exactly what the user's shell runs.
	runSession("sh -c 'echo Ran echo!; echo to-stderr >&2'")
	runSession("sh -c 'echo unclosed-quote")

	var firstRecording string
	for i := range 2 {
		select {
		case recording := <-recordings:
			ch, recordedOutput := parseRecording(t, recording)
			if ch.SSHUser != sshUser {
				t.Errorf("SSHUser = %q; want %q", ch.SSHUser, sshUser)
			}
			wantCommand := ""
			if i == 0 {
				wantCommand = "sh -c 'echo Ran echo!; echo to-stderr >&2'"
				firstRecording = recordedOutput
			} else {
				wantCommand = "sh -c 'echo unclosed-quote"
			}
			if ch.Command != wantCommand {
				t.Errorf("Command = %q; want %q", ch.Command, wantCommand)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for recording")
		}
	}

	// Both stdout and stderr must be captured in the recording. On non-PTY
	// sessions stderr is a separate stream; it must still flow through the
	// recording writer (recorded under the "o" output direction).
	if !strings.Contains(firstRecording, "Ran echo!") {
		t.Errorf("recording missing stdout output %q; got %q", "Ran echo!", firstRecording)
	}
	if !strings.Contains(firstRecording, "to-stderr") {
		t.Errorf("recording missing stderr output %q; got %q", "to-stderr", firstRecording)
	}
}

// TestSSHSFTPRecording pins that sftp-subsystem sessions are subject to
// the recording policy. With recorders configured, an sftp session
// uploads a metadata-only cast (CastHeader identifying the peer, local
// user, and connection, with Command "sftp"; no I/O events — the SFTP
// wire protocol is binary). With an unreachable recorder and
// RejectSessionWithMessage, the session is refused (exit 254) instead
// of running silently unrecorded. With no recorders configured, sftp
// sessions are unchanged (no recording setup, no rejection).
func TestSSHSFTPRecording(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; only runs on linux and darwin", runtime.GOOS)
	}

	recordings := make(chan []byte, 2)
	recordingServer := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		recordings <- b
	})
	recorderAddr := must.Get(netip.ParseAddrPort(recordingServer.Listener.Addr().String()))

	// An unreachable recorder: a port with nothing listening on it.
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadRecorder := must.Get(netip.ParseAddrPort(deadLn.Addr().String()))
	deadLn.Close()

	newServer := func(recorders []netip.AddrPort) *server {
		s := &server{
			logf: tstest.WhileTestRunningLogger(t),
			lb: &localState{
				sshEnabled: true,
				varRoot:    t.TempDir(),
				matchingRule: newSSHRule(&tailcfg.SSHAction{
					Accept:    true,
					Recorders: recorders,
					OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
						RejectSessionWithMessage:    "session rejected",
						TerminateSessionWithMessage: "session terminated",
					},
				}),
			},
		}
		t.Cleanup(s.Shutdown)
		return s
	}

	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	const sshUser = "alice"
	cfg := &testssh.ClientConfig{
		User:            sshUser,
		HostKeyCallback: testssh.InsecureIgnoreHostKey(),
	}

	// runSFTP opens an sftp-subsystem session and returns the exit status
	// the server sent and the channel output. With no tailscaled on PATH the
	// sftp child can't be launched, so a session that gets past the
	// recording gate exits 1 with no user-visible output; a session refused
	// by the recording policy exits 254 with the policy's message.
	runSFTP := func(s *server) (int, string) {
		t.Helper()
		sc, dc := memnet.NewTCPConn(src, dst, 1024)
		if err := sc.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
			t.Fatal(err)
		}
		type result struct {
			status int
			out    string
		}
		resCh := make(chan result, 1)
		go func() {
			c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
			if err != nil {
				t.Errorf("client: %v", err)
				return
			}
			client := testssh.NewClient(c, chans, reqs)
			defer client.Close()
			status, out := sftpSubsystemSession(t, client)
			resCh <- result{status, out}
		}()
		if err := s.HandleSSHConn(dc); err != nil {
			t.Errorf("HandleSSHConn: %v", err)
		}
		select {
		case res := <-resCh:
			return res.status, res.out
		case <-time.After(60 * time.Second):
			t.Fatal("sftp session did not finish")
			return -1, ""
		}
	}

	t.Run("metadata-only", func(t *testing.T) {
		s := newServer([]netip.AddrPort{recorderAddr})
		status, out := runSFTP(s)
		if status != 1 {
			t.Errorf("exit status = %d; want 1 (sftp child launch failure, not recording rejection). output %q", status, out)
		}
		if strings.Contains(out, "session rejected") {
			t.Errorf("sftp session was refused by the recording policy; want it to proceed to the (unavailable) sftp child: %q", out)
		}

		select {
		case b := <-recordings:
			ch, recordedOutput := parseRecording(t, b)
			if ch.Command != "sftp" {
				t.Errorf("CastHeader.Command = %q; want %q", ch.Command, "sftp")
			}
			if ch.SSHUser != sshUser {
				t.Errorf("CastHeader.SSHUser = %q; want %q", ch.SSHUser, sshUser)
			}
			if recordedOutput != "" {
				t.Errorf("metadata-only sftp recording contains output events %q; want none", recordedOutput)
			}
			if rest := restOfRecording(t, b); rest != "" {
				t.Errorf("sftp recording has cast lines after the header; want none: %q", rest)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for sftp recording upload")
		}
	})

	t.Run("recorder-unreachable-rejects", func(t *testing.T) {
		s := newServer([]netip.AddrPort{deadRecorder})
		status, out := runSFTP(s)
		if status != 254 {
			t.Errorf("exit status = %d; want 254 (recording-required session denied). output %q", status, out)
		}
		if !strings.HasSuffix(out, "session rejected\r\n") {
			t.Errorf("client output = %q; want it to end with %q", out, "session rejected\r\n")
		}
	})

	t.Run("no-recorders-unchanged", func(t *testing.T) {
		s := newServer(nil)
		status, out := runSFTP(s)
		if status != 1 {
			t.Errorf("exit status = %d; want 1 (sftp child launch failure, no recording involvement). output %q", status, out)
		}
		if strings.Contains(out, "session rejected") || strings.Contains(out, "recording") {
			t.Errorf("no-recorder sftp session touched the recording path: %q", out)
		}
	})
}

// sftpSubsystemSession opens a session channel on the client, requests
// the sftp subsystem, captures all channel output, and waits for the
// server's exit-status (or channel close). The testssh fork's Session
// helpers only cover exec/shell sessions; subsystem sessions need their
// own minimal request loop. The returned status is -1 if the channel
// closed without sending one.
func sftpSubsystemSession(t *testing.T, client *testssh.Client) (status int, out string) {
	t.Helper()
	ch, in, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Errorf("open session channel: %v", err)
		return -1, ""
	}
	defer ch.Close()

	var mu sync.Mutex
	var buf strings.Builder
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		io.Copy(&lockedWriter{mu: &mu, w: &buf}, ch)
	}()
	// Refusal messages (e.g. "tailscale: access revoked") are written
	// to the channel's stderr stream. Capture extended data too. The
	// stderr copier gets its own done channel. The wait loop below
	// lets it drain before the deferred channel Close runs.
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		io.Copy(&lockedWriter{mu: &mu, w: &buf}, ch.Stderr())
	}()

	ok, err := ch.SendRequest("subsystem", true, testssh.Marshal(&struct{ Subsystem string }{Subsystem: "sftp"}))
	if err != nil || !ok {
		t.Errorf("sftp subsystem request: ok=%v, err=%v", ok, err)
		return -1, ""
	}

	statusCh := make(chan int, 1)
	go func() {
		st := -1
		for r := range in {
			if r.Type == "exit-status" && len(r.Payload) >= 4 {
				st = int(binary.BigEndian.Uint32(r.Payload))
				break
			}
		}
		statusCh <- st
	}()
	select {
	case status = <-statusCh:
	case <-time.After(60 * time.Second):
		t.Errorf("sftp session did not exit")
		return -1, ""
	}
	// Let both copiers drain whatever the server wrote before the
	// exit-status request before the deferred channel Close cuts it off.
	for _, done := range []chan struct{}{copyDone, stderrDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	return status, buf.String()
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *strings.Builder
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// restOfRecording returns everything after the (first line of the)
// recording's cast header, i.e. any recorded I/O events.
func restOfRecording(t *testing.T, recording []byte) string {
	t.Helper()
	i := bytes.IndexByte(recording, '\n')
	if i == -1 {
		return ""
	}
	return strings.TrimSpace(string(recording[i+1:]))
}

// parseRecording parses a session recording, returning its CastHeader and the
// concatenation of all recorded output.
//
// The recording is a stream of newline-separated JSON: the CastHeader,
// followed by asciinema cast lines of the form [time, "o", data].
func parseRecording(t *testing.T, recording []byte) (sessionrecording.CastHeader, string) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(recording))
	var ch sessionrecording.CastHeader
	if err := dec.Decode(&ch); err != nil {
		t.Fatalf("decoding cast header: %v", err)
	}
	var output strings.Builder
	for dec.More() {
		var line []any
		if err := dec.Decode(&line); err != nil {
			t.Fatalf("decoding cast line: %v", err)
		}
		if len(line) != 3 {
			continue
		}
		if dir, _ := line[1].(string); dir != "o" {
			continue
		}
		if data, ok := line[2].(string); ok {
			output.WriteString(data)
		}
	}
	return ch, output.String()
}

func TestSSHAuthFlow(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("skipping on %q; only runs on linux and darwin", runtime.GOOS)
	}
	varRoot := t.TempDir()
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
	autogroupNonrootRule := newSSHRule(&tailcfg.SSHAction{
		Accept:  true,
		Message: "autogroup:nonroot",
	})
	autogroupNonrootRule.SSHUsers = map[string]string{"*": "="}
	// Maps the requested user to a local user that does not exist, so the
	// post-accept local-user lookup fails; pins that the client-visible
	// banner is the fixed lookup-failure message, never the error cause.
	lookupFailRule := newSSHRule(&tailcfg.SSHAction{
		Accept: true,
	})
	lookupFailRule.SSHUsers = map[string]string{"alice": "no-such-local-user-tailssh-test"}

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
				varRoot:    varRoot,
			},
			authErr:     true,
			wantBanners: []string{"tailscale: tailnet policy does not permit you to SSH to this node\n"},
		},
		{
			name: "user-mismatch",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: bobRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "alice"` + "\n"},
		},
		{
			name:    "user-mismatch-numeric-username",
			sshUser: "321",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: bobRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "321"` + "\n"},
		},
		{
			name:    "user-mismatch-root-uid",
			sshUser: "0",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: autogroupNonrootRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "0"` + "\n"},
		},
		{
			name:    "user-mismatch-root-uid-leading-space",
			sshUser: " 0",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: autogroupNonrootRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user " 0"` + "\n"},
		},
		{
			name:    "user-mismatch-root-uid-force-password-auth",
			sshUser: "0+password",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: autogroupNonrootRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "0"` + "\n"},
		},
		{
			name:    "user-mismatch-double-zero-force-password-auth",
			sshUser: "00+password",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: autogroupNonrootRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "00"` + "\n"},
		},
		{
			name:    "user-mismatch-leading-plus",
			sshUser: "+0",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: autogroupNonrootRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "+0"` + "\n"},
		},
		{
			// The "=" mapping forces a local lookup of a user that does not
			// exist; the banner must be the same policy-rejection shape as
			// the other user-mismatch cases, never a lookup-failure variant.
			name:    "user-mismatch-no-such-local-user",
			sshUser: "no-such-local-user-tailssh-test",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: autogroupNonrootRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: tailnet policy does not permit you to SSH as user "no-such-local-user-tailssh-test"` + "\n"},
		},
		{
			// Accepted by policy, but the mapped local user does not exist:
			// the client sees one fixed message regardless of why the
			// lookup failed (the cause goes to the server log only).
			name:    "accept-local-user-lookup-fails",
			sshUser: "alice",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: lookupFailRule,
			},
			authErr:     true,
			wantBanners: []string{`tailscale: failed to look up local user "no-such-local-user-tailssh-test" ` + "\n"},
		},
		{
			name: "accept",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: acceptRule,
			},
			wantBanners: []string{"Welcome to Tailscale SSH!"},
		},
		{
			name: "reject",
			state: &localState{
				sshEnabled:   true,
				varRoot:      varRoot,
				matchingRule: rejectRule,
			},
			wantBanners: []string{"Go Away!"},
			authErr:     true,
		},
		{
			name: "simple-check",
			state: &localState{
				sshEnabled: true,
				varRoot:    varRoot,
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
				varRoot:    varRoot,
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
				varRoot:    varRoot,
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
				varRoot:      varRoot,
				matchingRule: acceptRule,
			},
			usesPassword: true,
			wantBanners:  []string{"Welcome to Tailscale SSH!"},
		},
	}
	src, dst := must.Get(netip.ParseAddrPort("100.100.100.101:2231")), must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	for _, tc := range tests {
		for _, authMethods := range [][]string{nil, {"publickey", "password"}, {"password", "publickey"}} {
			t.Run(fmt.Sprintf("%s-skip-none-auth-%v", tc.name, strings.Join(authMethods, "-then-")), func(t *testing.T) {
				// A fresh server per subtest: clientAuth's go recheckPolicy
				// outlives the subtest's conn and races a shared server's
				// swapped lb/logf between subtests.
				s := &server{
					logf: tstest.WhileTestRunningLogger(t),
					lb:   tc.state,
				}
				defer s.Shutdown()

				sc, dc := memnet.NewTCPConn(src, dst, 1024)
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
				wg.Go(func() {
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
				})
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
	h := newTestSSHHarness(t)
	u, execSSH := h.user, h.execSSH

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
		if before, after, ok := bytes.Cut(line, []byte{'='}); ok {
			e[string(before)] = string(after)
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
		{"TERM=xterm-256color", true},
		// TERM is a capability name, not a path.
		{"TERM=a/b", false},
		// Locale names reach root su/login environments where glibc treats
		// path-like values as locale-data paths and leading dashes as its
		// own options.
		{"LANG=en_US.UTF-8", true},
		{"LANG=../..", false},
		{"LANG=../../x", false},
		{"LANG=/x", false},
		{"LANG=-x", false},
		{"LC_FOO=-x", false},
		{"LC_FOO=en_US", true},
		{"LC_FOO=a/b", false},
		// NUL would truncate on exec.
		{"TERM=x\x00y", false},
		{"LANG=x\x00y", false},
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

func TestOnPolicyChangeSkipsPreAuthConns(t *testing.T) {
	tests := []struct {
		name       string
		sshRule    *tailcfg.SSHRule
		wantCancel bool
	}{
		{
			name:       "accept-after-auth",
			sshRule:    newSSHRule(&tailcfg.SSHAction{Accept: true}),
			wantCancel: false,
		},
		{
			name:       "reject-after-auth",
			sshRule:    newSSHRule(&tailcfg.SSHAction{Reject: true}),
			wantCancel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				srv := &server{
					logf: tstest.WhileTestRunningLogger(t),
					lb: &localState{
						sshEnabled:   true,
						matchingRule: tt.sshRule,
					},
				}
				// An authed conn carries the grant and the looked-up local user
				// it latched at auth time.
				latched := &tailcfg.SSHAction{Accept: true}
				lu, err := userLookup(currentUser)
				if err != nil {
					t.Skipf("no local user %q: %v", currentUser, err)
				}
				c := &conn{
					srv:         srv,
					action0:     latched,
					finalAction: latched,
					info: &sshConnInfo{
						sshUser: "alice",
						src:     netip.MustParseAddrPort("1.2.3.4:30343"),
						dst:     netip.MustParseAddrPort("100.100.100.102:22"),
					},
					localUser: lu,
					// Latch the auth-time policy spelling for this synthetic conn.
					mappedLocalUser: tt.sshRule.SSHUsers["alice"],
				}
				srv.activeConns = map[*conn]bool{c: true}
				ctx, cancel := context.WithCancelCause(context.Background())
				ss := &sshSession{ctx: ctx, cancelCtx: cancel}
				c.sessions = []*sshSession{ss}

				// Before authCompleted is set, OnPolicyChange should skip
				// the conn entirely — no goroutine spawned.
				srv.OnPolicyChange()
				synctest.Wait()
				select {
				case <-ctx.Done():
					t.Fatal("session canceled before auth completed")
				default:
				}

				// Mark auth as completed. Now OnPolicyChange should
				// evaluate the policy and act accordingly.
				c.authCompleted.Store(true)

				srv.OnPolicyChange()
				synctest.Wait()
				select {
				case <-ctx.Done():
					if !tt.wantCancel {
						t.Fatal("valid session should not have been canceled")
					}
				default:
					if tt.wantCancel {
						t.Fatal("invalid session should have been canceled")
					}
				}
			})
		})
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

func TestIsRootUser(t *testing.T) {
	tests := []struct {
		uid, username string
		want          bool
	}{
		{uid: "0", username: "root", want: true},
		{uid: "0", username: "alice", want: true},
		// A non-canonical numeric uid 0 is also root.
		{uid: "00", username: "alice", want: true},
		{uid: "+0", username: "alice", want: true},
		{uid: "-0", username: "alice", want: true},
		{uid: "0b0", username: "alice", want: true},
		{uid: "0B0", username: "alice", want: true},
		{uid: "0o0", username: "alice", want: true},
		{uid: "0O0", username: "alice", want: true},
		{uid: "0x0", username: "alice", want: true},
		{uid: "0X0", username: "alice", want: true},
		{uid: "-0x0", username: "alice", want: true},
		{uid: "0_0", username: "alice", want: true},
		{uid: "0x_0", username: "alice", want: true},
		{uid: "00000000", username: "alice", want: true},
		{uid: "1000", username: "root", want: true},
		{uid: "1000", username: "alice", want: false},
		{uid: "1", username: "daemon", want: false},
		// Non-numeric uids keep the string behavior.
		{uid: "notanumber", username: "root", want: true},
		{uid: "notanumber", username: "alice", want: false},
	}
	for _, tt := range tests {
		got := isRootUser(&userMeta{User: user.User{Uid: tt.uid, Username: tt.username}})
		if got != tt.want {
			t.Errorf("isRootUser(uid=%q, username=%q) = %v; want %v", tt.uid, tt.username, got, tt.want)
		}
	}
}
