// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios)

package tailssh

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gliderssh "github.com/tailscale/gliderssh"
	gossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// TestSessionMonitorMandatedTerminationThenDisconnect checks that duration
// and recording failures terminate the target after an immediate disconnect
// while preserving unrelated jobs.
func TestSessionMonitorMandatedTerminationThenDisconnect(t *testing.T) {
	for _, mode := range []string{"duration", "recording"} {
		t.Run(mode, func(t *testing.T) {
			action := &tailcfg.SSHAction{Accept: true}
			message := "Session timeout"
			release := func() {}
			if mode == "duration" {
				action.SessionDuration = 2 * time.Second
			} else {
				message = "recording failed"
				released := make(chan struct{})
				release = sync.OnceFunc(func() { close(released) })
				// Release the upload before waiting for recorder handlers during cleanup.
				recorder := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.(http.Flusher).Flush()
					if _, err := bufio.NewReader(r.Body).ReadBytes('\n'); err != nil {
						return
					}
					<-released
					io.WriteString(w, "{invalid ack}\n")
					w.(http.Flusher).Flush()
				})
				t.Cleanup(release)
				action.Recorders = []netip.AddrPort{netip.MustParseAddrPort(recorder.Listener.Addr().String())}
				action.OnRecordingFailure = &tailcfg.SSHRecorderFailureAction{TerminateSessionWithMessage: message}
			}
			connCh := make(chan *conn, 1)
			addr := newMonitorSessionServerFor(t, nil, nil, &tailcfg.SSHRule{
				SSHUsers: map[string]string{},
				Action:   action,
			}, false, func(c *conn, s gliderssh.Session) {
				connCh <- c
				c.newSSHSession(s).run()
			})
			cl, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
				Timeout:         10 * time.Second,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Close()
			s, err := cl.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			stdout, err := s.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := s.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Start("trap '' HUP; echo $$; exec sleep 300"); err != nil {
				t.Fatal(err)
			}
			targetCh := make(chan int, 1)
			go func() {
				line, _ := bufio.NewReader(stdout).ReadString('\n')
				pid, _ := strconv.Atoi(strings.TrimSpace(line))
				targetCh <- pid
			}()
			var target int
			select {
			case target = <-targetCh:
				if target <= 1 {
					t.Fatalf("invalid target PID %d", target)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("session did not start")
			}
			c := <-connCh
			mc := c.connMonitorIfAny()
			if mc == nil {
				t.Fatal("session has no monitor")
			}
			// The unrelated job uses default SIGHUP handling.
			sibling, err := mc.Exec(mustCtx(t), []string{"/bin/sleep", "300"}, nil, "/", false, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = unix.Kill(-sibling.PID, unix.SIGKILL)
				_ = unix.Kill(-target, unix.SIGKILL)
			})
			messageCh := make(chan bool, 1)
			go func() {
				r := bufio.NewReader(stderr)
				for {
					line, err := r.ReadString('\n')
					if strings.Contains(line, message) {
						messageCh <- true
						return
					}
					if err != nil {
						messageCh <- false
						return
					}
				}
			}()
			release()
			select {
			case ok := <-messageCh:
				if !ok {
					t.Fatal("session ended without its termination message")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("termination message did not arrive")
			}
			cl.Close()
			c.closeConnMonitor()
			if err := tstest.WaitFor(5*time.Second, func() error {
				if !pidGone(target) {
					return fmt.Errorf("mandated target %d survived disconnect", target)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(200 * time.Millisecond)
			if pidGone(sibling.PID) {
				t.Fatalf("unrelated job %d killed on graceful close", sibling.PID)
			}
		})
	}
}
