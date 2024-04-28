// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build integrationtest
// +build integrationtest

package tailssh

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/sftp"
	gossh "github.com/tailscale/golang-x-crypto/ssh"
	"golang.org/x/crypto/ssh"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
)

// This file contains integration tests of the SSH functionality. These tests
// exercise everything except for the authentication logic.
//
// The tests make the following assumptions about the environment:
//
// - OS is one of MacOS or Linux
// - Test is being run as root (e.g. go test -tags integrationtest -c . && sudo ./tailssh.test -test.run TestIntegration)
// - TAILSCALED_PATH environment variable points at tailscaled binary
// - User "testuser" exists
// - "testuser" is in groups "groupone" and "grouptwo"

func TestMain(m *testing.M) {
	// Create our log file.
	file, err := os.OpenFile("/tmp/tailscalessh.log", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	file.Close()

	// Tail our log file.
	cmd := exec.Command("tail", "-f", "/tmp/tailscalessh.log")

	r, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(r)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			log.Println(line)
		}
	}()

	err = cmd.Start()
	if err != nil {
		return
	}

	m.Run()
}

func TestIntegrationSSH(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	homeDir := "/home/testuser"
	if runtime.GOOS == "darwin" {
		homeDir = "/Users/testuser"
	}

	tests := []struct {
		cmd  string
		want []string
	}{
		{
			cmd:  "id",
			want: []string{"testuser", "groupone", "grouptwo"},
		},
		{
			cmd:  "pwd",
			want: []string{homeDir},
		},
	}

	for _, test := range tests {
		// run every test both without and with a shell
		for _, shell := range []bool{false, true} {
			shellQualifier := "no_shell"
			if shell {
				shellQualifier = "shell"
			}

			t.Run(fmt.Sprintf("%s_%s", test.cmd, shellQualifier), func(t *testing.T) {
				s := testSession(t)

				if shell {
					err := s.RequestPty("xterm", 40, 80, ssh.TerminalModes{
						ssh.ECHO:          1,
						ssh.TTY_OP_ISPEED: 14400,
						ssh.TTY_OP_OSPEED: 14400,
					})
					if err != nil {
						t.Fatalf("unable to request shell: %s", err)
					}
				}

				got := s.run(t, test.cmd)
				for _, want := range test.want {
					if !strings.Contains(got, want) {
						t.Errorf("%q does not contain %q", got, want)
					}
				}
			})
		}
	}
}

func TestIntegrationSFTP(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	filePath := "/tmp/sftptest.dat"
	wantText := "hello world"

	cl := testClient(t)
	scl, err := sftp.NewClient(cl)
	if err != nil {
		t.Fatalf("can't get sftp client: %s", err)
	}

	file, err := scl.Create(filePath)
	if err != nil {
		t.Fatalf("can't create file: %s", err)
	}
	_, err = file.Write([]byte(wantText))
	if err != nil {
		t.Fatalf("can't write to file: %s", err)
	}
	err = file.Close()
	if err != nil {
		t.Fatalf("can't close file: %s", err)
	}

	file, err = scl.OpenFile(filePath, os.O_RDONLY)
	if err != nil {
		t.Fatalf("can't open file: %s", err)
	}
	defer file.Close()
	gotText, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("can't read file: %s", err)
	}
	if diff := cmp.Diff(string(gotText), wantText); diff != "" {
		t.Fatalf("unexpected file contents (-got +want):\n%s", diff)
	}

	s := testSessionFor(t, cl)
	got := s.run(t, "ls -l "+filePath)
	if !strings.Contains(got, "testuser") {
		t.Fatalf("unexpected file owner user: %s", got)
	} else if !strings.Contains(got, "testuser") {
		t.Fatalf("unexpected file owner group: %s", got)
	}
}

type session struct {
	*ssh.Session

	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (s *session) run(t *testing.T, cmdString string) string {
	t.Helper()

	err := s.Start(cmdString)
	if err != nil {
		t.Fatalf("unable to start command: %s", err)
	}

	ch := make(chan []byte)
	go func() {
		for {
			b := make([]byte, 1)
			n, err := s.stdout.Read(b)
			if n > 0 {
				ch <- b
			}
			if err == io.EOF {
				return
			}
		}
	}()

	// Read first byte in blocking fashion.
	_got := <-ch

	// Read subsequent bytes in non-blocking fashion.
readLoop:
	for {
		select {
		case b := <-ch:
			_got = append(_got, b...)
		case <-time.After(25 * time.Millisecond):
			break readLoop
		}
	}

	return string(_got)
}

func testClient(t *testing.T) *ssh.Client {
	t.Helper()

	username := "testuser"
	srv := &server{
		lb:             &testBackend{localUser: username},
		logf:           log.Printf,
		tailscaledPath: os.Getenv("TAILSCALED_PATH"),
		timeNow:        time.Now,
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		conn, err := l.Accept()
		if err == nil {
			go srv.HandleSSHConn(&addressFakingConn{conn})
		}
	}()

	cl, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	return cl
}

func testSession(t *testing.T) *session {
	cl := testClient(t)
	return testSessionFor(t, cl)
}

func testSessionFor(t *testing.T, cl *ssh.Client) *session {
	s, err := cl.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	stdinReader, stdinWriter := io.Pipe()
	stdoutReader, stdoutWriter := io.Pipe()
	stderrReader, stderrWriter := io.Pipe()
	s.Stdin = stdinReader
	s.Stdout = io.MultiWriter(stdoutWriter, os.Stdout)
	s.Stderr = io.MultiWriter(stderrWriter, os.Stderr)
	return &session{
		Session: s,
		stdin:   stdinWriter,
		stdout:  stdoutReader,
		stderr:  stderrReader,
	}
}

// testBackend implements ipnLocalBackend
type testBackend struct {
	localUser string
}

func (tb *testBackend) GetSSH_HostKeys() ([]gossh.Signer, error) {
	var result []gossh.Signer
	for _, typ := range []string{"ed25519", "ecdsa", "rsa"} {
		var priv any
		var err error
		switch typ {
		case "ed25519":
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		case "ecdsa":
			curve := elliptic.P256()
			priv, err = ecdsa.GenerateKey(curve, rand.Reader)
		case "rsa":
			const keySize = 2048
			priv, err = rsa.GenerateKey(rand.Reader, keySize)
		}
		if err != nil {
			return nil, err
		}
		mk, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		hostKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mk})
		signer, err := gossh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, err
		}
		result = append(result, signer)
	}
	return result, nil
}

func (tb *testBackend) ShouldRunSSH() bool {
	return true
}

func (tb *testBackend) NetMap() *netmap.NetworkMap {
	return &netmap.NetworkMap{
		SSHPolicy: &tailcfg.SSHPolicy{
			Rules: []*tailcfg.SSHRule{
				&tailcfg.SSHRule{
					Principals: []*tailcfg.SSHPrincipal{{Any: true}},
					Action:     &tailcfg.SSHAction{Accept: true},
					SSHUsers:   map[string]string{"*": tb.localUser},
				},
			},
		},
	}
}

func (tb *testBackend) WhoIs(ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
	return (&tailcfg.Node{}).View(), tailcfg.UserProfile{
		LoginName: tb.localUser + "@example.com",
	}, true
}

func (tb *testBackend) DoNoiseRequest(req *http.Request) (*http.Response, error) {
	return nil, nil
}

func (tb *testBackend) Dialer() *tsdial.Dialer {
	return nil
}

func (tb *testBackend) TailscaleVarRoot() string {
	return ""
}

func (tb *testBackend) NodeKey() key.NodePublic {
	return key.NodePublic{}
}

type addressFakingConn struct {
	net.Conn
}

func (conn *addressFakingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("100.100.100.101"),
		Port: 22,
	}
}

func (conn *addressFakingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("100.100.100.102"),
		Port: 10002,
	}
}
