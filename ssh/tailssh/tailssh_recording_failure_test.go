// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || darwin

package tailssh

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"tailscale.com/net/memnet"
	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
	"tailscale.com/tstest"
	"tailscale.com/util/must"
)

type blockingRecordingNotifyState struct {
	*localState
	entered chan time.Time // notification request deadline
	release chan struct{}
}

func (b *blockingRecordingNotifyState) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/recording-failed" {
		return b.localState.DoNoiseRequest(req)
	}
	deadline, _ := req.Context().Deadline()
	b.entered <- deadline
	select {
	case <-b.release:
		return nil, errors.New("test: notification released")
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
}

func TestSSHRecordingUploadFailureTerminatesWhileNotifyBlocked(t *testing.T) {
	testSSHRecordingUploadFailureWhileNotifyBlocked(t, true)
}

func TestSSHRecordingUploadFailureFailsOpenWhileNotifyBlocked(t *testing.T) {
	testSSHRecordingUploadFailureWhileNotifyBlocked(t, false)
}

func testSSHRecordingUploadFailureWhileNotifyBlocked(t *testing.T, terminate bool) {
	if runtime.GOOS == "darwin" {
		t.Skip("requires the Linux direct-exec test path")
	}
	gotHeader := make(chan struct{})
	releaseRecorder := make(chan struct{})
	releaseUpload := sync.OnceFunc(func() { close(releaseRecorder) })
	recorder := mockRecordingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if _, err := bufio.NewReader(r.Body).ReadBytes('\n'); err != nil {
			t.Errorf("read cast header: %v", err)
			return
		}
		close(gotHeader)
		<-releaseRecorder
		// The upload was accepted; now fail while the session is live.
		io.WriteString(w, "{invalid ack}\n")
		w.(http.Flusher).Flush()
	})

	onFailure := &tailcfg.SSHRecorderFailureAction{NotifyURL: "https://unused/recording-failed"}
	if terminate {
		onFailure.TerminateSessionWithMessage = "session terminated"
	}
	lb := &blockingRecordingNotifyState{
		localState: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
			matchingRule: newSSHRule(&tailcfg.SSHAction{
				Accept:             true,
				Recorders:          []netip.AddrPort{must.Get(netip.ParseAddrPort(recorder.Listener.Addr().String()))},
				OnRecordingFailure: onFailure,
			}),
		},
		entered: make(chan time.Time, 1),
		release: make(chan struct{}),
	}
	s := &server{logf: tstest.WhileTestRunningLogger(t), lb: lb}
	defer func() {
		releaseUpload()
		close(lb.release)
		s.Shutdown()
	}()

	src := must.Get(netip.ParseAddrPort("100.100.100.101:2231"))
	dst := must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	sc, dc := memnet.NewTCPConn(src, dst, 1024)
	defer sc.Close()
	_ = sc.SetDeadline(time.Now().Add(12 * time.Second))
	clientReady := make(chan error, 1)
	type result struct {
		stdout, stderr []byte
		err            error
	}
	clientDone := make(chan result, 1)
	go func() {
		cfg := &testssh.ClientConfig{User: "alice", HostKeyCallback: testssh.InsecureIgnoreHostKey()}
		c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
		if err != nil {
			clientReady <- err
			return
		}
		client := testssh.NewClient(c, chans, reqs)
		defer client.Close()
		session, err := client.NewSession()
		if err != nil {
			clientReady <- err
			return
		}
		defer session.Close()
		stdout, err := session.StdoutPipe()
		if err != nil {
			clientReady <- err
			return
		}
		stderr, err := session.StderrPipe()
		if err != nil {
			clientReady <- err
			return
		}
		command := "echo ready; exec sleep 20"
		if !terminate {
			command = "echo ready; sleep 1; echo alive"
		}
		if err := session.Start(command); err != nil {
			clientReady <- err
			return
		}
		stdoutReader := bufio.NewReader(stdout)
		line, err := stdoutReader.ReadString('\n')
		if line != "ready\n" && err == nil {
			err = errors.New("unexpected command output: " + line)
		}
		clientReady <- err
		out, readErr := io.ReadAll(stdoutReader)
		if readErr != nil {
			clientDone <- result{err: readErr}
			return
		}
		errOut, readErr := io.ReadAll(stderr)
		if readErr != nil {
			clientDone <- result{stdout: out, err: readErr}
			return
		}
		clientDone <- result{stdout: out, stderr: errOut, err: session.Wait()}
	}()
	handleDone := make(chan error, 1)
	go func() { handleDone <- s.HandleSSHConn(dc) }()
	select {
	case <-gotHeader:
	case <-time.After(5 * time.Second):
		t.Fatal("recorder did not receive cast header")
	}
	// Ensure the command is active before ending the accepted recorder upload.
	select {
	case err := <-clientReady:
		if err != nil {
			t.Fatalf("command did not start: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("command did not start")
	}
	releaseUpload()
	select {
	case deadline := <-lb.entered:
		if until := time.Until(deadline); until <= 0 || until > 6*time.Second {
			t.Errorf("recording failure notification deadline in %v; want within 5s", until)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recording failure notification was not attempted")
	}
	select {
	case res := <-clientDone:
		if terminate {
			if !strings.Contains(string(res.stderr), "session terminated") || res.err == nil {
				t.Errorf("stdout = %q, stderr = %q, err = %v; want termination", res.stdout, res.stderr, res.err)
			}
		} else if !strings.Contains(string(res.stdout), "alive") || len(res.stderr) != 0 || res.err != nil {
			t.Errorf("stdout = %q, stderr = %q, err = %v; want fail-open completion", res.stdout, res.stderr, res.err)
		}
	case <-time.After(3 * time.Second):
		t.Error("session remained active while recording-failure notification was blocked")
	}
	select {
	case err := <-handleDone:
		if err != nil {
			t.Errorf("HandleSSHConn: %v", err)
		}
	default:
	}
}

func TestSSHSFTPRecordingRejectionStderr(t *testing.T) {
	deadLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadRecorder := must.Get(netip.ParseAddrPort(deadLn.Addr().String()))
	deadLn.Close()

	s := &server{
		logf: tstest.WhileTestRunningLogger(t),
		lb: &localState{
			sshEnabled: true,
			varRoot:    t.TempDir(),
			matchingRule: newSSHRule(&tailcfg.SSHAction{
				Accept:    true,
				Recorders: []netip.AddrPort{deadRecorder},
				OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
					RejectSessionWithMessage: "session rejected",
				},
			}),
		},
	}
	defer s.Shutdown()
	src := must.Get(netip.ParseAddrPort("100.100.100.101:2231"))
	dst := must.Get(netip.ParseAddrPort("100.100.100.102:22"))
	sc, dc := memnet.NewTCPConn(src, dst, 1024)
	defer sc.Close()
	_ = sc.SetDeadline(time.Now().Add(10 * time.Second))
	clientDone := make(chan error, 1)
	go func() {
		cfg := &testssh.ClientConfig{User: "alice", HostKeyCallback: testssh.InsecureIgnoreHostKey()}
		c, chans, reqs, err := testssh.NewClientConn(sc, sc.RemoteAddr().String(), cfg)
		if err != nil {
			clientDone <- err
			return
		}
		client := testssh.NewClient(c, chans, reqs)
		defer client.Close()
		ch, in, err := client.OpenChannel("session", nil)
		if err != nil {
			clientDone <- err
			return
		}
		defer ch.Close()
		var stdout bytes.Buffer
		stderrDone := make(chan []byte, 1)
		go func() {
			out, _ := io.ReadAll(ch.Stderr())
			stderrDone <- out
		}()
		ok, err := ch.SendRequest("subsystem", true, testssh.Marshal(&struct{ Subsystem string }{Subsystem: "sftp"}))
		if err != nil || !ok {
			clientDone <- errors.New("sftp subsystem request failed")
			return
		}
		// Use the real SFTP client: a text rejection on stdout looks like a
		// malformed binary version packet; stderr must remain readable.
		sftpClient, sftpErr := sftp.NewClientPipe(io.TeeReader(ch, &stdout), ch)
		if sftpClient != nil {
			sftpClient.Close()
			clientDone <- errors.New("SFTP unexpectedly initialized")
			return
		}
		if sftpErr == nil {
			clientDone <- errors.New("SFTP initialized without a server")
			return
		}
		status := -1
		for req := range in {
			if req.Type == "exit-status" && len(req.Payload) >= 4 {
				status = int(binary.BigEndian.Uint32(req.Payload))
			}
		}
		stderr := <-stderrDone
		if status != 254 || stdout.Len() != 0 || string(stderr) != "session rejected\r\n" {
			clientDone <- fmt.Errorf("want exit 254 and rejection on stderr only; got status=%d, stdout=%q, stderr=%q, SFTP error=%v", status, stdout.String(), stderr, sftpErr)
			return
		}
		clientDone <- nil
	}()
	if err := s.HandleSSHConn(dc); err != nil {
		t.Errorf("HandleSSHConn: %v", err)
	}
	select {
	case err := <-clientDone:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SFTP client did not receive recording rejection")
	}
}
