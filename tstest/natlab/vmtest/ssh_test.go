// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/mds/shell"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// TestTailscaleSSH exercises the Tailscale SSH server ("tailscale up --ssh",
// not a system sshd) on both Ubuntu and gokrazy nodes, with an Ubuntu node
// as the SSH client.
//
// On Ubuntu it tests logging in as both root and a non-root user, which
// exercises the incubator's su-based login path.
//
// On gokrazy it exercises the gokrazy special cases in the SSH code:
// util/osuser hard-codes the login shell to /tmp/serial-busybox/ash and
// falls back to a synthesized root user (uid 0, home dir "/") when user
// lookup fails, since gokrazy has no user database; and the incubator's
// findSU refuses to use su on gokrazy, so sessions are handled in-process.
func TestTailscaleSSH(t *testing.T) {
	env := vmtest.New(t)
	client := sshTestNode(env, "client", vmtest.Ubuntu2404)
	ubuntu := sshTestNode(env, "ubuntu", vmtest.Ubuntu2404, vmtest.TailscaleSSH())
	gokrazy := sshTestNode(env, "gokrazy", vmtest.Gokrazy, vmtest.TailscaleSSH())
	env.Start()

	if out, err := env.SSHExec(ubuntu, "useradd -m -s /bin/bash tsuser"); err != nil {
		t.Fatalf("useradd: %v\n%s", err, out)
	}

	ubuntuIP := tailscaleIP4(t, env, ubuntu)
	gokrazyIP := tailscaleIP4(t, env, gokrazy)

	// ssh runs cmd as user on the node at ip over Tailscale SSH, from the
	// client node, returning the combined output and the ssh client's exit
	// code. The command run via Env.SSHExec always exits 0 so that its
	// transport-error (exit 255) retry loop doesn't kick in when a
	// Tailscale SSH connection is expected to fail.
	const exitMarker = "tailscale-ssh-exit="
	ssh := func(user string, ip netip.Addr, cmd string) (string, int) {
		t.Helper()
		inner := "ssh" +
			" -o StrictHostKeyChecking=no" +
			" -o UserKnownHostsFile=/dev/null" +
			" -o BatchMode=yes" +
			" -o ConnectTimeout=10" +
			" -o LogLevel=ERROR" +
			" " + user + "@" + ip.String() +
			" " + shell.Quote(cmd)
		out, err := env.SSHExec(client, inner+" 2>&1; echo "+exitMarker+"$?")
		if err != nil {
			t.Fatalf("ssh %s@%s: %v\n%s", user, ip, err, out)
		}
		i := strings.LastIndex(out, exitMarker)
		if i == -1 {
			t.Fatalf("ssh %s@%s: no exit marker in output:\n%s", user, ip, out)
		}
		code, err := strconv.Atoi(strings.TrimSpace(out[i+len(exitMarker):]))
		if err != nil {
			t.Fatalf("ssh %s@%s: bad exit marker in output:\n%s", user, ip, out)
		}
		return strings.TrimSpace(out[:i]), code
	}

	// waitSSH waits for the node's Tailscale SSH server to accept a
	// connection; the first one can race tailscaled's SSH server startup
	// and WireGuard path setup.
	waitSSH := func(name, user string, ip netip.Addr) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Minute)
		for {
			out, code := ssh(user, ip, "echo ok")
			if code == 0 && strings.Contains(out, "ok") {
				t.Logf("[%s] Tailscale SSH up as %s@%s", name, user, ip)
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("[%s] Tailscale SSH as %s@%s never came up; last output (exit %d):\n%s", name, user, ip, code, out)
			}
			time.Sleep(2 * time.Second)
		}
	}
	waitSSH("ubuntu", "root", ubuntuIP)
	waitSSH("gokrazy", "root", gokrazyIP)

	check := func(desc, user string, ip netip.Addr, cmd, want string) {
		t.Helper()
		out, code := ssh(user, ip, cmd)
		if code != 0 {
			t.Errorf("%s: ssh %s@%s %q exited %d:\n%s", desc, user, ip, cmd, code, out)
			return
		}
		if out != want {
			t.Errorf("%s: ssh %s@%s %q = %q, want %q", desc, user, ip, cmd, out, want)
		}
	}

	check("ubuntu root login", "root", ubuntuIP, "id -un && pwd", "root\n/root")
	check("ubuntu non-root login", "tsuser", ubuntuIP, "id -un && pwd", "tsuser\n/home/tsuser")

	// A nonexistent user is rejected on Ubuntu...
	if out, code := ssh("nosuchuser", ubuntuIP, "true"); code == 0 {
		t.Errorf("ubuntu nonexistent user: ssh succeeded, want failure:\n%s", out)
	}

	// ... but on gokrazy any username works and becomes root, via the
	// synthesized-user fallback in util/osuser (uid 0, home dir "/").
	// $0 is the login shell the session ran the command with, which on
	// gokrazy is hard-coded rather than looked up with getent. These
	// sessions also implicitly exercise the incubator's su-less
	// in-process path, since gokrazy has no su.
	check("gokrazy root login shell", "root", gokrazyIP, "echo $0", "/tmp/serial-busybox/ash")
	check("gokrazy nonexistent user maps to root", "nosuchuser", gokrazyIP, "pwd", "/")
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
