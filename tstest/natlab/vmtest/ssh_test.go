// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/mds/shell"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestTailscaleSSH_Ubuntu exercises the Tailscale SSH server ("tailscale up
// --ssh", not a system sshd) on an Ubuntu node, with an Ubuntu node as the SSH
// client. It tests logging in as both root and a non-root user, which
// exercises the incubator's su-based login path, and then runs subtests
// covering the SSH features that the real OpenSSH client uses across the
// real tailnet.
func TestTailscaleSSH_Ubuntu(t *testing.T) {
	testSuite := newTestSuite(t, "ubuntu", vmtest.Ubuntu2404)

	ubuntu := testSuite.server

	if out, err := testSuite.env.SSHExec(ubuntu, "useradd -m -s /bin/bash tsuser"); err != nil {
		t.Fatalf("useradd: %v\n%s", err, out)
	}

	testSuite.waitSSH(t, "ubuntu", "root")

	testSuite.check(t, "ubuntu root login", "root", "id -un && pwd", "root\n/root")
	testSuite.check(t, "ubuntu non-root login", "tsuser", "id -un && pwd", "tsuser\n/home/tsuser")

	if out, code := testSuite.ssh(t, "nosuchuser", "true"); code == 0 {
		t.Errorf("ubuntu nonexistent user: ssh succeeded, want failure:\n%s", out)
	}

	testSuite.enableSSHEnvironmentVariables(t)
	testSuite.setPolicy(t, featurePolicy())

	t.Run("PTY", testSuite.testPTY)
	t.Run("ExitCodes", testSuite.testExitCodes)
	t.Run("SFTP", testSuite.testSFTP)
	t.Run("SCP", testSuite.testSCP)
	t.Run("AgentForwarding", testSuite.testAgentForwarding)
	t.Run("AcceptEnv", testSuite.testAcceptEnv)
	t.Run("LargeTransfer", testSuite.testLargeTransfer)
	t.Run("ControlMaster", testSuite.testControlMaster)
	t.Run("LocalPortForwarding", testSuite.testLocalPortForwarding)
	t.Run("RemotePortForwarding", testSuite.testRemotePortForwarding)
	t.Run("TailscaleSSHCommand", testSuite.testTailscaleSSHCommand)
	t.Run("Banners", testSuite.testBanners)
	t.Run("UserMapping", testSuite.testUserMapping)
	t.Run("RevokeActiveSession", testSuite.testRevokeActiveSession)
	t.Run("CheckMode", testSuite.testCheckMode)
	t.Run("Recording", testSuite.testRecording)

	testSuite.checkAutogroupNonroot(t, "ubuntu")
}

// TestTailscaleSSH_FreeBSD exercises the Tailscale SSH server ("tailscale up
// --ssh", not a system sshd) on a FreeBSD node, with an Ubuntu node as the SSH
// client. It tests logging in as both root and a non-root user, which
// exercises the incubator's su-based login path.
func TestTailscaleSSH_FreeBSD(t *testing.T) {
	testSuite := newTestSuite(t, "freebsd", vmtest.FreeBSD150)

	freebsd := testSuite.server

	if out, err := testSuite.env.SSHExec(freebsd, "pw useradd tsuser -m"); err != nil {
		t.Fatalf("pw useradd: %v\n%s", err, out)
	}

	testSuite.waitSSH(t, "freebsd", "root")

	testSuite.check(t, "freebsd root login", "root", "id -un && pwd", "root\n/root")
	testSuite.check(t, "freebsd non-root login", "tsuser", "id -un && pwd", "tsuser\n/home/tsuser")

	if out, code := testSuite.ssh(t, "nosuchuser", "true"); code == 0 {
		t.Errorf("freebsd nonexistent user: ssh succeeded, want failure:\n%s", out)
	}

	t.Run("PTY", testSuite.testPTY)
	t.Run("SFTP", testSuite.testSFTP)

	testSuite.checkAutogroupNonroot(t, "freebsd")
}

// TestTailscaleSSH_Gokrazy exercises the gokrazy-specific cases in the
// Tailscale SSH server ("tailscale up --ssh", not a system sshd), with an
// Ubuntu node as the SSH client. util/osuser hard-codes the login shell to
// /tmp/serial-busybox/ash and falls back to a synthesized root user (uid 0,
// home dir "/") when user lookup fails, since gokrazy has no user database;
// and the incubator's findSU refuses to use su on gokrazy, so sessions are
// handled in-process.
func TestTailscaleSSH_Gokrazy(t *testing.T) {
	testSuite := newTestSuite(t, "gokrazy", vmtest.Gokrazy)

	testSuite.waitSSH(t, "gokrazy", "root")

	// $0 is the login shell the session ran the command with, which on gokrazy
	// is hard-coded rather than looked up with getent. These sessions also
	// implicitly exercise the incubator's su-less in-process path, since
	// gokrazy has no su.
	testSuite.check(t, "gokrazy root login shell", "root", "echo $0", "/tmp/serial-busybox/ash")
	testSuite.check(t, "gokrazy nonexistent user maps to root", "nosuchuser", "pwd", "/")
}

// exitMarker precedes the exit code of a script run by [sshTest.run]. The
// script's wrapper always exits 0 so that [vmtest.Env.SSHExec]'s
// transport-error (exit 255) retry loop doesn't kick in when a Tailscale SSH
// connection is expected to fail.
const exitMarker = "tailscale-ssh-exit="

// sshOpts are the OpenSSH client options used for every connection from
// [sshTest.client] to [sshTest.server].
const sshOpts = " -o StrictHostKeyChecking=no" +
	" -o UserKnownHostsFile=/dev/null" +
	" -o BatchMode=yes" +
	" -o ConnectTimeout=10" +
	" -o LogLevel=ERROR"

type sshTest struct {
	client   *vmtest.Node
	server   *vmtest.Node
	clientIP netip.Addr // client's Tailscale IPv4 address
	serverIP netip.Addr // server's Tailscale IPv4 address
	env      *vmtest.Env

	// serverDNSName is the server's MagicDNS name, with a trailing dot.
	serverDNSName string
}

// dest returns the "user@host" argument for connecting as user to
// [sshTest.server].
func (st *sshTest) dest(user string) string {
	return user + "@" + st.serverIP.String()
}

// sshCmd returns the shell command line that runs the OpenSSH client on
// [sshTest.client] to connect as user to [sshTest.server] over Tailscale SSH.
// The extra arguments come before [sshOpts], so "-o" options in extra take
// precedence, as ssh uses the first value it sees for each option. The caller
// appends the remote command, if any.
func (st *sshTest) sshCmd(user string, extra ...string) string {
	args := append([]string{"ssh"}, extra...)
	args = append(args, strings.TrimSpace(sshOpts), st.dest(user))
	return strings.Join(args, " ")
}

// run runs the shell script as root on [sshTest.client] via its debug SSH
// NIC, returning the script's combined stdout and stderr (trimmed of
// surrounding whitespace) and its exit code.
func (st *sshTest) run(t *testing.T, script string) (string, int) {
	t.Helper()
	out, err := st.env.SSHExec(st.client, "(\n"+script+"\n) 2>&1; echo "+exitMarker+"$?")
	if err != nil {
		t.Fatalf("running on client: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	i := strings.LastIndex(out, exitMarker)
	if i == -1 {
		t.Fatalf("no exit marker in output of script:\n%s\noutput:\n%s", script, out)
	}
	code, err := strconv.Atoi(strings.TrimSpace(out[i+len(exitMarker):]))
	if err != nil {
		t.Fatalf("bad exit marker in output of script:\n%s\noutput:\n%s", script, out)
	}
	return strings.TrimSpace(out[:i]), code
}

// mustRun is like [sshTest.run] but fails the test if the script exits
// non-zero.
func (st *sshTest) mustRun(t *testing.T, script string) string {
	t.Helper()
	out, code := st.run(t, script)
	if code != 0 {
		t.Fatalf("script exited %d:\n%s\noutput:\n%s", code, script, out)
	}
	return out
}

// ssh runs cmd as user on [sshTest.server] over Tailscale SSH, from the
// client node, returning the combined output and the ssh client's exit
// code.
func (st *sshTest) ssh(t *testing.T, user string, cmd string) (string, int) {
	t.Helper()
	return st.run(t, st.sshCmd(user)+" "+shell.Quote(cmd))
}

// mustSSH is like [sshTest.ssh] but fails the test if ssh exits non-zero.
func (st *sshTest) mustSSH(t *testing.T, user string, cmd string) string {
	t.Helper()
	out, code := st.ssh(t, user, cmd)
	if code != 0 {
		t.Fatalf("ssh %s %q exited %d:\n%s", st.dest(user), cmd, code, out)
	}
	return out
}

// serverExec runs cmd as root on [sshTest.server] via its debug SSH NIC,
// not over Tailscale SSH, failing the test if it fails.
func (st *sshTest) serverExec(t *testing.T, cmd string) string {
	t.Helper()
	out, err := st.env.SSHExec(st.server, cmd)
	if err != nil {
		t.Fatalf("running %q on server: %v\n%s", cmd, err, out)
	}
	return strings.TrimSpace(out)
}

// waitSSH waits for the node's Tailscale SSH server to accept a
// connection; the first one can race tailscaled's SSH server startup
// and WireGuard path setup.
func (st *sshTest) waitSSH(t *testing.T, name, user string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		out, code := st.ssh(t, user, "echo ok")
		if code == 0 && strings.Contains(out, "ok") {
			t.Logf("[%s] Tailscale SSH up as %s@%s", name, user, st.serverIP)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("[%s] Tailscale SSH as %s@%s never came up; last output (exit %d):\n%s", name, user, st.serverIP, code, out)
		}
		time.Sleep(2 * time.Second)
	}
}

// check attempts to execute a command as specified user on the server, failing
// if the output isn't what is expected.
func (st *sshTest) check(t *testing.T, desc, user string, cmd, want string) {
	t.Helper()
	out, code := st.ssh(t, user, cmd)
	if code != 0 {
		t.Errorf("%s: ssh %s@%s %q exited %d:\n%s", desc, user, st.serverIP, cmd, code, out)
		return
	}
	if out != want {
		t.Errorf("%s: ssh %s@%s %q = %q, want %q", desc, user, st.serverIP, cmd, out, want)
	}
}

// setPolicy sets the tailnet's SSH policy and waits for it to reach
// [sshTest.server]'s netmap, so that new connections are evaluated against
// it.
func (st *sshTest) setPolicy(t *testing.T, policy *tailcfg.SSHPolicy) {
	t.Helper()
	st.env.ControlServer().SetSSHPolicy(policy)
	want, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := st.env.Tailscale(st.server, "debug", "netmap")
		if err != nil {
			return err
		}
		var nm struct {
			SSHPolicy *tailcfg.SSHPolicy
		}
		if err := json.Unmarshal([]byte(out), &nm); err != nil {
			return err
		}
		got, err := json.Marshal(nm.SSHPolicy)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return fmt.Errorf("server has SSH policy %s; want %s", got, want)
		}
		return nil
	}); err != nil {
		t.Fatalf("SSH policy never reached server: %v", err)
	}
}

// withPolicy sets the tailnet's SSH policy, like [sshTest.setPolicy], and
// restores the previous policy when t finishes.
func (st *sshTest) withPolicy(t *testing.T, policy *tailcfg.SSHPolicy) {
	t.Helper()
	old := st.env.ControlServer().SSHPolicy
	st.setPolicy(t, policy)
	t.Cleanup(func() { st.setPolicy(t, old) })
}

// checkAutogroupNonroot adjusts the server's SSH policy to be equivalent to "autogroup:nonroot"
// and verifies that attempting to SSH as root fails.
func (st *sshTest) checkAutogroupNonroot(t *testing.T, name string) {
	t.Helper()
	orignalSSHPolicy := st.env.ControlServer().SSHPolicy
	defer func() {
		st.env.ControlServer().SetSSHPolicy(orignalSSHPolicy)
	}()

	st.env.ControlServer().SetSSHPolicy(&tailcfg.SSHPolicy{
		Rules: []*tailcfg.SSHRule{{
			Principals: []*tailcfg.SSHPrincipal{{Any: true}},
			SSHUsers:   map[string]string{"*": "="},
			Action:     &tailcfg.SSHAction{Accept: true},
		}},
	})

	if err := tstest.WaitFor(30*time.Second, func() error {
		_, code := st.ssh(t, "root", "true")
		if code == 0 {
			return fmt.Errorf("root SSH still succeeds")
		}
		return nil
	}); err != nil {
		t.Fatalf("%s: root SSH still succeeds after policy update to autogroup:nonroot-only; policy may not have propagated", name)
	}
}

func newTestSuite(t *testing.T, serverName string, serverOS vmtest.OSImage) *sshTest {
	t.Helper()
	env := vmtest.New(t)
	client := sshTestNode(env, "client", vmtest.Ubuntu2404)
	server := sshTestNode(env, serverName, serverOS, vmtest.TailscaleSSH())
	env.Start()

	return &sshTest{
		client:        client,
		server:        server,
		clientIP:      tailscaleIP4(t, env, client),
		serverIP:      tailscaleIP4(t, env, server),
		env:           env,
		serverDNSName: env.Status(server).Self.DNSName,
	}
}

// sshTestNode adds a node named name running img behind its own
// easy-NAT network.
func sshTestNode(env *vmtest.Env, name string, img vmtest.OSImage, opts ...any) *vmtest.Node {
	n := env.NumNodes()
	opts = append([]any{
		env.AddNetwork(
			fmt.Sprintf("2.%d.%d.%d", n, n, n), // public IP
			fmt.Sprintf("192.168.%d.1/24", n), vnet.EasyNAT),
		vmtest.OS(img),
	}, opts...)
	return env.AddNode(name, opts...)
}

// tailscaleIP4 returns the node's IPv4 Tailscale address.
func tailscaleIP4(t *testing.T, env *vmtest.Env, n *vmtest.Node) netip.Addr {
	t.Helper()
	st := env.Status(n)
	for _, ip := range st.Self.TailscaleIPs {
		if ip.Is4() {
			return ip
		}
	}
	t.Fatalf("no IPv4 Tailscale address for %s; have %v", n.Name(), st.Self.TailscaleIPs)
	panic("unreachable")
}
