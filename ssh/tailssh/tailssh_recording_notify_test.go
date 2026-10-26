// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"runtime"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
)

// recordingNotifyCaptureState observes a notification while control is blocked
// and records why the request eventually returns.
type recordingNotifyCaptureState struct {
	*blockingRecordingNotifyState
	requests chan *http.Request
	results  chan error
}

func (b *recordingNotifyCaptureState) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/recording-failed" {
		return b.localState.DoNoiseRequest(req)
	}
	b.requests <- req
	resp, err := b.blockingRecordingNotifyState.DoNoiseRequest(req)
	b.results <- err
	return resp, err
}

func newRecordingNotifyCaptureState(ls *localState) *recordingNotifyCaptureState {
	return &recordingNotifyCaptureState{
		blockingRecordingNotifyState: &blockingRecordingNotifyState{
			localState: ls,
			entered:    make(chan time.Time, 1),
			release:    make(chan struct{}),
		},
		requests: make(chan *http.Request, 1),
		results:  make(chan error, 1),
	}
}

// TestRecordingNotifyTimeout tests the timeout with virtual time, including
// session cancellation at exactly the notification deadline. A notification
// using a background context must survive session cancellation, but it must
// honor cancellation or an earlier deadline on its own parent context.
func TestRecordingNotifyTimeout(t *testing.T) {
	for _, mode := range []string{"timeout", "parent-deadline", "parent-cancel", "simultaneous-parent-cancel", "session-cancel", "simultaneous-session-cancel"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lb := newRecordingNotifyCaptureState(new(localState))
				sessionCtx, cancelSession := context.WithCancel(context.Background())
				defer cancelSession()
				ss := &sshSession{
					ctx:  sessionCtx,
					logf: t.Logf,
					conn: &conn{
						srv:       &server{lb: lb},
						localUser: new(userMeta),
						info:      &sshConnInfo{node: (&tailcfg.Node{ID: 1}).View()},
					},
				}
				ctx := context.Background()
				wantDuration := 5 * time.Second
				var wantErr error = context.DeadlineExceeded
				switch mode {
				case "parent-deadline":
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, time.Second)
					defer cancel()
					wantDuration = time.Second
				case "parent-cancel", "simultaneous-parent-cancel":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					defer cancel()
					if mode == "parent-cancel" {
						wantDuration, wantErr = time.Second, context.Canceled
					}
					defer time.AfterFunc(wantDuration, cancel).Stop()
				case "session-cancel":
					defer time.AfterFunc(time.Second, cancelSession).Stop()
				case "simultaneous-session-cancel":
					defer time.AfterFunc(5*time.Second, cancelSession).Stop()
				}
				start := time.Now()
				ss.notifyControl(ctx, key.NodePublic{}, tailcfg.SSHSessionRecordingFailed, nil, "https://unused/recording-failed")
				synctest.Wait()
				if elapsed := time.Since(start); elapsed != wantDuration {
					t.Errorf("notification duration = %v; want %v", elapsed, wantDuration)
				}
				err := <-lb.results
				if mode == "simultaneous-parent-cancel" {
					// Either timer can win; both must end the request at 5s.
					if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
						t.Errorf("notification error = %v; want cancellation or deadline", err)
					}
				} else if !errors.Is(err, wantErr) {
					t.Errorf("notification error = %v; want %v", err, wantErr)
				}
				if mode == "timeout" && sessionCtx.Err() != nil {
					t.Errorf("notification timeout canceled session: %v", sessionCtx.Err())
				}
			})
		})
	}
}

// TestSSHRecordingConnectFailureNotifyTimeout exercises the synchronous startup
// path. Rejection and fail-open startup must both finish when a stuck control
// notification times out, with no upload watcher or duplicate notification.
func TestSSHRecordingConnectFailureNotifyTimeout(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires the Linux direct-exec test path")
	}
	for _, reject := range []bool{true, false} {
		name := "fail-open"
		if reject {
			name = "reject"
		}
		t.Run(name, func(t *testing.T) {
			recorder := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			})
			onFailure := &tailcfg.SSHRecorderFailureAction{NotifyURL: "https://unused/recording-failed"}
			if reject {
				onFailure.RejectSessionWithMessage = "session rejected"
			}
			lb := newRecordingNotifyCaptureState(&localState{
				sshEnabled: true,
				varRoot:    t.TempDir(),
				matchingRule: newSSHRule(&tailcfg.SSHAction{
					Accept:             true,
					Recorders:          []netip.AddrPort{netip.MustParseAddrPort(recorder.Listener.Addr().String())},
					OnRecordingFailure: onFailure,
				}),
			})
			s := &server{logf: tstest.WhileTestRunningLogger(t), lb: lb}
			defer func() {
				close(lb.release)
				s.Shutdown()
			}()
			sc, dc := memnet.NewTCPConn(netip.MustParseAddrPort("100.100.100.101:2231"), netip.MustParseAddrPort("100.100.100.102:22"), 1024)
			defer sc.Close()
			defer dc.Close()
			if err := sc.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
				t.Fatal(err)
			}
			type result struct {
				out []byte
				err error
			}
			clientDone := make(chan result, 1)
			go func() {
				c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), &testssh.ClientConfig{
					User: "alice", HostKeyCallback: testssh.InsecureIgnoreHostKey(),
				})
				if err != nil {
					clientDone <- result{err: err}
					return
				}
				client := testssh.NewClient(c, chans, reqs)
				defer client.Close()
				session, err := client.NewSession()
				if err != nil {
					clientDone <- result{err: err}
					return
				}
				defer session.Close()
				out, err := session.CombinedOutput("echo ran")
				clientDone <- result{out, err}
			}()
			handleDone := make(chan error, 1)
			go func() { handleDone <- s.HandleSSHConn(dc) }()
			var req *http.Request
			select {
			case req = <-lb.requests:
			case <-time.After(10 * time.Second):
				t.Fatal("recording failure notification was not attempted")
			}
			if _, ok := req.Context().Deadline(); !ok {
				t.Fatal("connect-failure notification has no deadline")
			}
			var event tailcfg.SSHEventNotifyRequest
			if err := json.NewDecoder(req.Body).Decode(&event); err != nil {
				t.Fatal(err)
			}
			wantEvent := tailcfg.SSHSessionRecordingFailed
			if reject {
				wantEvent = tailcfg.SSHSessionRecordingRejected
			}
			if event.EventType != wantEvent || len(event.RecordingAttempts) != 1 || event.RecordingAttempts[0].FailureMessage == "" {
				t.Fatalf("unexpected connect-failure notification: %+v", event)
			}
			// Allow margin beyond the five-second request deadline so a test
			// timeout cannot race the behavior it is checking.
			select {
			case res := <-clientDone:
				if reject {
					ee, ok := res.err.(*testssh.ExitError)
					if !ok || ee.ExitStatus() != 254 || string(res.out) != "session rejected\r\n" {
						t.Errorf("rejected session = %q, %v; want rejection and exit 254", res.out, res.err)
					}
				} else if res.err != nil || string(res.out) != "ran\n" {
					t.Errorf("fail-open session = %q, %v; want command output and success", res.out, res.err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("session remained blocked on control notification")
			}
			select {
			case err := <-lb.results:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("notification error = %v; want deadline exceeded", err)
				}
			default:
				t.Fatal("session completed before notification returned")
			}
			select {
			case err := <-handleDone:
				if err != nil {
					t.Errorf("HandleSSHConn: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("SSH handler did not finish")
			}
			if len(lb.requests) != 0 {
				t.Error("unexpected second recording failure notification")
			}
		})
	}
}
