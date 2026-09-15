// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package integration

import (
	"errors"
	"net"
	"os/user"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/integration/testcontrol"
)

// TestTailscaleSSH runs "tailscale up --ssh" on one node and connects to it
// over the tailnet from a second node, running a command as the user
// tailscaled itself runs as. That is the one user every tailscaled can run
// sessions as: a non-root Unix tailscaled and a non-LocalSystem Windows
// tailscaled cannot switch users. On Windows, when the server node runs as a
// service (see --run-windows-service-tests), tailscaled is LocalSystem and the
// session instead exercises the S4U logon of the test user.
func TestTailscaleSSH(t *testing.T) {
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd", "windows":
	default:
		t.Skipf("Tailscale SSH server not supported on %s", runtime.GOOS)
	}
	tstest.Parallel(t)

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	env := NewTestEnv(t, ConfigureControl(func(s *testcontrol.Server) {
		// Any tailnet identity may SSH in as any name; it always runs as
		// the test's user.
		s.SSHPolicy = &tailcfg.SSHPolicy{
			Rules: []*tailcfg.SSHRule{{
				Principals: []*tailcfg.SSHPrincipal{{Any: true}},
				SSHUsers:   map[string]string{"*": u.Username},
				Action:     &tailcfg.SSHAction{Accept: true},
			}},
		}
	}))

	// The server node is created first so that it takes the TUN slot (and
	// so runs as a Windows service) when TUN mode is available; the client
	// node then runs in userspace mode, which is what gives it a SOCKS5
	// proxy for the test to dial through.
	server := NewTestNode(t, env)
	client := NewTestNode(t, env, TUNMode(false))
	clientSocksCh := client.socks5AddrChan()

	server.StartDaemon()
	client.StartDaemon()
	server.AwaitListening()
	client.AwaitListening()
	server.MustUp("--ssh")
	client.MustUp()
	server.AwaitRunning()
	client.AwaitRunning()

	serverIP := server.AwaitIP4()
	socksAddr := client.AwaitSocksAddr(clientSocksCh)
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	// The first connection may race the server's netmap and packet filter
	// updates; keep trying until a session runs.
	var sshClient *ssh.Client
	if err := tstest.WaitFor(60*time.Second, func() error {
		c, err := dialer.Dial("tcp", net.JoinHostPort(serverIP.String(), "22"))
		if err != nil {
			return err
		}
		cc, chans, reqs, err := ssh.NewClientConn(c, serverIP.String()+":22", &ssh.ClientConfig{
			User:            u.Username,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         10 * time.Second,
		})
		if err != nil {
			c.Close()
			return err
		}
		sshClient = ssh.NewClient(cc, chans, reqs)
		return nil
	}); err != nil {
		t.Fatalf("connecting to Tailscale SSH on %v: %v", serverIP, err)
	}
	defer sshClient.Close()

	// "echo hello" and "exit 7" mean the same thing in sh, PowerShell,
	// and cmd.exe, so the same test works whatever the server's shell is.
	t.Run("stdout", func(t *testing.T) {
		out, err := runSSH(sshClient, "echo hello")
		if err != nil {
			t.Fatalf("echo: %v; output %q", err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "hello" {
			t.Errorf("output = %q; want %q", got, "hello")
		}
	})
	t.Run("exit_code", func(t *testing.T) {
		out, err := runSSH(sshClient, "exit 7")
		var ee *ssh.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("got err %v (output %q); want an ssh.ExitError", err, out)
		}
		if ee.ExitStatus() != 7 {
			t.Errorf("exit status = %d; want 7", ee.ExitStatus())
		}
	})
	t.Run("pty", func(t *testing.T) {
		sess, err := sshClient.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
			t.Fatal(err)
		}
		out, err := sess.CombinedOutput("echo hello")
		if err != nil {
			t.Fatalf("echo with pty: %v; output %q", err, out)
		}
		if !strings.Contains(string(out), "hello") {
			t.Errorf("pty output %q does not contain %q", out, "hello")
		}
	})
}

// runSSH runs cmd in a new session on c and returns its combined output.
func runSSH(c *ssh.Client, cmd string) ([]byte, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return sess.CombinedOutput(cmd)
}
