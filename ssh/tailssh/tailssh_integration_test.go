// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build integrationtest
// +build integrationtest

package tailssh

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bramvdbogaerde/go-scp"
	"github.com/google/go-cmp/cmp"
	"github.com/pkg/sftp"
	gossh "github.com/tailscale/golang-x-crypto/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	glider "tailscale.com/tempfork/gliderlabs/ssh"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/set"
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
	cmd := exec.Command("tail", "-F", "/tmp/tailscalessh.log")

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
	defer func() {
		// tail -f has a default sleep interval of 1 second, so it takes a
		// moment for it to finish reading our log file after we've terminated.
		// So, wait a bit to let it catch up.
		time.Sleep(2 * time.Second)
	}()

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
		cmd             string
		want            []string
		forceV1Behavior bool
		skip            bool
		allowSendEnv    bool
	}{
		{
			cmd:             "id",
			want:            []string{"testuser", "groupone", "grouptwo"},
			forceV1Behavior: false,
		},
		{
			cmd:             "id",
			want:            []string{"testuser", "groupone", "grouptwo"},
			forceV1Behavior: true,
		},
		{
			cmd:             "pwd",
			want:            []string{homeDir},
			skip:            os.Getenv("SKIP_FILE_OPS") == "1" || !fallbackToSUAvailable(),
			forceV1Behavior: false,
		},
		{
			cmd:             "echo 'hello'",
			want:            []string{"hello"},
			skip:            os.Getenv("SKIP_FILE_OPS") == "1" || !fallbackToSUAvailable(),
			forceV1Behavior: false,
		},
		{
			cmd:             `echo "${GIT_ENV_VAR:-unset1} ${EXACT_MATCH:-unset2} ${TESTING:-unset3} ${NOT_ALLOWED:-unset4}"`,
			want:            []string{"working1 working2 working3 unset4"},
			forceV1Behavior: false,
			allowSendEnv:    true,
		},
		{
			cmd:             `echo "${GIT_ENV_VAR:-unset1} ${EXACT_MATCH:-unset2} ${TESTING:-unset3} ${NOT_ALLOWED:-unset4}"`,
			want:            []string{"unset1 unset2 unset3 unset4"},
			forceV1Behavior: false,
			allowSendEnv:    false,
		},
	}

	for _, test := range tests {
		if test.skip {
			continue
		}

		// run every test both without and with a shell
		for _, shell := range []bool{false, true} {
			shellQualifier := "no_shell"
			if shell {
				shellQualifier = "shell"
			}

			versionQualifier := "v2"
			if test.forceV1Behavior {
				versionQualifier = "v1"
			}

			t.Run(fmt.Sprintf("%s_%s_%s", test.cmd, shellQualifier, versionQualifier), func(t *testing.T) {
				sendEnv := map[string]string{
					"GIT_ENV_VAR": "working1",
					"EXACT_MATCH": "working2",
					"TESTING":     "working3",
					"NOT_ALLOWED": "working4",
				}
				s := testSession(t, test.forceV1Behavior, test.allowSendEnv, sendEnv)

				if shell {
					err := s.RequestPty("xterm", 40, 80, ssh.TerminalModes{
						ssh.ECHO:          1,
						ssh.TTY_OP_ISPEED: 14400,
						ssh.TTY_OP_OSPEED: 14400,
					})
					if err != nil {
						t.Fatalf("unable to request PTY: %s", err)
					}

					err = s.Shell()
					if err != nil {
						t.Fatalf("unable to request shell: %s", err)
					}

					// Read the shell prompt
					s.read()
				}

				got := s.run(t, test.cmd, shell)
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

	for _, forceV1Behavior := range []bool{false, true} {
		name := "v2"
		if forceV1Behavior {
			name = "v1"
		}
		t.Run(name, func(t *testing.T) {
			filePath := "/home/testuser/sftptest.dat"
			if forceV1Behavior || !fallbackToSUAvailable() {
				filePath = "/tmp/sftptest.dat"
			}
			wantText := "hello world"

			cl := testClient(t, forceV1Behavior, false)
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

			s := testSessionFor(t, cl, nil)
			got := s.run(t, "ls -l "+filePath, false)
			if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner user: %s", got)
			} else if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner group: %s", got)
			}
		})
	}
}

func TestIntegrationSCP(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	for _, forceV1Behavior := range []bool{false, true} {
		name := "v2"
		if forceV1Behavior {
			name = "v1"
		}
		t.Run(name, func(t *testing.T) {
			filePath := "/home/testuser/scptest.dat"
			if !fallbackToSUAvailable() {
				filePath = "/tmp/scptest.dat"
			}
			wantText := "hello world"

			cl := testClient(t, forceV1Behavior, false)
			scl, err := scp.NewClientBySSH(cl)
			if err != nil {
				t.Fatalf("can't get sftp client: %s", err)
			}

			err = scl.Copy(context.Background(), strings.NewReader(wantText), filePath, "0644", int64(len(wantText)))
			if err != nil {
				t.Fatalf("can't create file: %s", err)
			}

			outfile, err := os.CreateTemp("", "")
			if err != nil {
				t.Fatalf("can't create temp file: %s", err)
			}
			err = scl.CopyFromRemote(context.Background(), outfile, filePath)
			if err != nil {
				t.Fatalf("can't copy file from remote: %s", err)
			}
			outfile.Close()

			gotText, err := os.ReadFile(outfile.Name())
			if err != nil {
				t.Fatalf("can't read file: %s", err)
			}
			if diff := cmp.Diff(string(gotText), wantText); diff != "" {
				t.Fatalf("unexpected file contents (-got +want):\n%s", diff)
			}

			s := testSessionFor(t, cl, nil)
			got := s.run(t, "ls -l "+filePath, false)
			if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner user: %s", got)
			} else if !strings.Contains(got, "testuser") {
				t.Fatalf("unexpected file owner group: %s", got)
			}
		})
	}
}

func TestSSHAgentForwarding(t *testing.T) {
	debugTest.Store(true)
	t.Cleanup(func() {
		debugTest.Store(false)
	})

	// Create a client SSH key
	tmpDir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(tmpDir)
	})
	pkFile := filepath.Join(tmpDir, "pk")
	clientKey, clientKeyRSA := generateClientKey(t, pkFile)

	// Start upstream SSH server
	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatalf("unable to listen for SSH: %s", err)
	}
	t.Cleanup(func() {
		_ = l.Close()
	})

	// Run an SSH server that accepts connections from that client SSH key.
	gs := glider.Server{
		Handler: func(s glider.Session) {
			io.WriteString(s, "Hello world\n")
		},
		PublicKeyHandler: func(ctx glider.Context, key glider.PublicKey) error {
			// Note - this is not meant to be cryptographically secure, it's
			// just checking that SSH agent forwarding is forwarding the right
			// key.
			a := key.Marshal()
			b := clientKey.PublicKey().Marshal()
			if !bytes.Equal(a, b) {
				return errors.New("key mismatch")
			}
			return nil
		},
	}
	go gs.Serve(l)

	// Run tailscale SSH server and connect to it
	username := "testuser"
	tailscaleAddr := testServer(t, username, false, false)
	tcl, err := ssh.Dial("tcp", tailscaleAddr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcl.Close() })

	s, err := tcl.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	// Set up SSH agent forwarding on the client
	err = agent.RequestAgentForwarding(s)
	if err != nil {
		t.Fatal(err)
	}

	keyring := agent.NewKeyring()
	keyring.Add(agent.AddedKey{
		PrivateKey: clientKeyRSA,
	})
	err = agent.ForwardToAgent(tcl, keyring)
	if err != nil {
		t.Fatal(err)
	}

	// Attempt to SSH to the upstream test server using the forwarded SSH key
	// and run the "true" command.
	upstreamHost, upstreamPort, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	o, err := s.CombinedOutput(fmt.Sprintf(`ssh -T -o StrictHostKeyChecking=no -p %s upstreamuser@%s "true"`, upstreamPort, upstreamHost))
	if err != nil {
		t.Fatalf("unable to call true command: %s\n%s\n-------------------------", err, o)
	}
}

func fallbackToSUAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	_, err := exec.LookPath("su")
	if err != nil {
		return false
	}

	// Some operating systems like Fedora seem to require login to be present
	// in order for su to work.
	_, err = exec.LookPath("login")
	return err == nil
}

type session struct {
	*ssh.Session

	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

func (s *session) run(t *testing.T, cmdString string, shell bool) string {
	t.Helper()

	if shell {
		_, err := s.stdin.Write([]byte(fmt.Sprintf("%s\n", cmdString)))
		if err != nil {
			t.Fatalf("unable to send command to shell: %s", err)
		}
	} else {
		err := s.Start(cmdString)
		if err != nil {
			t.Fatalf("unable to start command: %s", err)
		}
	}

	return s.read()
}

func (s *session) read() string {
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
		case <-time.After(1 * time.Second):
			break readLoop
		}
	}

	return string(_got)
}

func testClient(t *testing.T, forceV1Behavior bool, allowSendEnv bool, authMethods ...ssh.AuthMethod) *ssh.Client {
	t.Helper()

	username := "testuser"
	addr := testServer(t, username, forceV1Behavior, allowSendEnv)

	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            authMethods,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })

	return cl
}

func testServer(t *testing.T, username string, forceV1Behavior bool, allowSendEnv bool) string {
	srv := &server{
		lb:             &testBackend{localUser: username, forceV1Behavior: forceV1Behavior, allowSendEnv: allowSendEnv},
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
		for {
			conn, err := l.Accept()
			if err == nil {
				go srv.HandleSSHConn(&addressFakingConn{conn})
			}
		}
	}()

	return l.Addr().String()
}

func testSession(t *testing.T, forceV1Behavior bool, allowSendEnv bool, sendEnv map[string]string) *session {
	cl := testClient(t, forceV1Behavior, allowSendEnv)
	return testSessionFor(t, cl, sendEnv)
}

func testSessionFor(t *testing.T, cl *ssh.Client, sendEnv map[string]string) *session {
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range sendEnv {
		s.Setenv(k, v)
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

func generateClientKey(t *testing.T, privateKeyFile string) (ssh.Signer, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mk})
	if privateKey == nil {
		t.Fatal("failed to encoded private key")
	}
	err = os.WriteFile(privateKeyFile, privateKey, 0600)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return signer, priv
}

// testBackend implements ipnLocalBackend
type testBackend struct {
	localUser       string
	forceV1Behavior bool
	allowSendEnv    bool
}

func (tb *testBackend) GetSSH_HostKeys() ([]gossh.Signer, error) {
	var result []gossh.Signer
	var priv any
	var err error
	const keySize = 2048
	priv, err = rsa.GenerateKey(rand.Reader, keySize)
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
	return result, nil
}

func (tb *testBackend) ShouldRunSSH() bool {
	return true
}

func (tb *testBackend) NetMap() *netmap.NetworkMap {
	capMap := make(set.Set[tailcfg.NodeCapability])
	if tb.forceV1Behavior {
		capMap[tailcfg.NodeAttrSSHBehaviorV1] = struct{}{}
	}
	if tb.allowSendEnv {
		capMap[tailcfg.NodeAttrSSHEnvironmentVariables] = struct{}{}
	}
	return &netmap.NetworkMap{
		SSHPolicy: &tailcfg.SSHPolicy{
			Rules: []*tailcfg.SSHRule{
				{
					Principals: []*tailcfg.SSHPrincipal{{Any: true}},
					Action:     &tailcfg.SSHAction{Accept: true, AllowAgentForwarding: true},
					SSHUsers:   map[string]string{"*": tb.localUser},
					AcceptEnv:  []string{"GIT_*", "EXACT_MATCH", "TEST?NG"},
				},
			},
		},
		AllCaps: capMap,
	}
}

func (tb *testBackend) WhoIs(_ string, ipp netip.AddrPort) (n tailcfg.NodeView, u tailcfg.UserProfile, ok bool) {
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
