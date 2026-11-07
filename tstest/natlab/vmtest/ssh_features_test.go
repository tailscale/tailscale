// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/mds/shell"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
)

// This file has the subtests of TestTailscaleSSH_Ubuntu (and some of
// TestTailscaleSSH_FreeBSD) that drive the OpenSSH client on the client VM
// through the tailnet to the server's Tailscale SSH server.

// anyPrincipal is an SSH policy principal list matching any connection.
var anyPrincipal = []*tailcfg.SSHPrincipal{{Any: true}}

// featurePolicy returns an SSH policy like the default one installed by
// [vmtest.TailscaleSSH], but which also permits agent forwarding and TCP port
// forwarding, and accepts the VMTEST_ACCEPTED environment variable.
func featurePolicy() *tailcfg.SSHPolicy {
	return &tailcfg.SSHPolicy{
		Rules: []*tailcfg.SSHRule{{
			Principals: anyPrincipal,
			SSHUsers:   map[string]string{"*": "=", "root": "root"},
			Action: &tailcfg.SSHAction{
				Accept:                    true,
				AllowAgentForwarding:      true,
				AllowLocalPortForwarding:  true,
				AllowRemotePortForwarding: true,
			},
			AcceptEnv: []string{"VMTEST_ACCEPTED"},
		}},
	}
}

// acceptPolicy returns an SSH policy with a single rule mapping users per
// sshUsers and applying action.
func acceptPolicy(sshUsers map[string]string, action *tailcfg.SSHAction) *tailcfg.SSHPolicy {
	return &tailcfg.SSHPolicy{
		Rules: []*tailcfg.SSHRule{{
			Principals: anyPrincipal,
			SSHUsers:   sshUsers,
			Action:     action,
		}},
	}
}

// enableSSHEnvironmentVariables grants the server the
// [tailcfg.NodeAttrSSHEnvironmentVariables] node attribute, without which
// Tailscale SSH ignores [tailcfg.SSHRule.AcceptEnv].
func (st *sshTest) enableSSHEnvironmentVariables(t *testing.T) {
	t.Helper()
	nodeKey := st.env.Status(st.server).Self.PublicKey
	st.env.ControlServer().SetNodeCapMap(nodeKey, tailcfg.NodeCapMap{
		tailcfg.NodeAttrSSHEnvironmentVariables: nil,
	})
	if err := tstest.WaitFor(30*time.Second, func() error {
		if !st.env.Status(st.server).Self.HasCap(tailcfg.NodeAttrSSHEnvironmentVariables) {
			return fmt.Errorf("server lacks %v", tailcfg.NodeAttrSSHEnvironmentVariables)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// checkContains reports a test error for each of wants that out doesn't
// contain.
func checkContains(t *testing.T, desc, out string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("%s: output does not contain %q:\n%s", desc, want, out)
		}
	}
}

// bgPrefix is the path prefix of the files that hold the output and exit
// code of a script started by [sshTest.startBackground].
const bgPrefix = "/tmp/vmtest-bg-"

// startBackground starts script in the background on [sshTest.client],
// recording its combined output and its exit code for
// [sshTest.backgroundOutput] and [sshTest.waitBackground].
func (st *sshTest) startBackground(t *testing.T, name, script string) {
	t.Helper()
	p := bgPrefix + name
	st.mustRun(t, fmt.Sprintf("rm -f %[1]s.out %[1]s.exit\n"+
		"( ( %[2]s ) >%[1]s.out 2>&1 </dev/null; echo $? >%[1]s.exit ) >/dev/null 2>&1 </dev/null &",
		p, script))
}

// backgroundOutput returns the output so far of the script started by
// [sshTest.startBackground] with the given name, and whether it has exited.
func (st *sshTest) backgroundOutput(t *testing.T, name string) (out string, exited bool) {
	t.Helper()
	p := bgPrefix + name
	out = st.mustRun(t, fmt.Sprintf("cat %[1]s.out; test -e %[1]s.exit && echo EXITED; true", p))
	out, exited = strings.CutSuffix(out, "EXITED")
	return strings.TrimSpace(out), exited
}

// waitBackground waits for the script started by [sshTest.startBackground]
// with the given name to exit, returning its combined output and exit code.
func (st *sshTest) waitBackground(t *testing.T, name string, timeout time.Duration) (string, int) {
	t.Helper()
	p := bgPrefix + name
	var codeStr string
	if err := tstest.WaitFor(timeout, func() error {
		out, code := st.run(t, "cat "+p+".exit")
		if code != 0 || out == "" {
			return fmt.Errorf("not done")
		}
		codeStr = out
		return nil
	}); err != nil {
		out, _ := st.backgroundOutput(t, name)
		t.Fatalf("background script %q still running after %v; output so far:\n%s", name, timeout, out)
	}
	code, err := strconv.Atoi(codeStr)
	if err != nil {
		t.Fatalf("bad exit code %q for background script %q", codeStr, name)
	}
	out, _ := st.backgroundOutput(t, name)
	return out, code
}

// ptyDriverPy runs the command in its arguments (an "ssh -tt" to an
// interactive shell) with pipes for stdin and stdout, and types the commands
// in $VMTEST_PTY_INPUT into it once the shell is reading input. Until then it
// types a probe command every second, since anything typed before the shell
// starts (while login(1) sets up the session) may be discarded. It prints the
// session's output and exits with the command's exit code, or 124 if the
// session doesn't finish within a minute.
const ptyDriverPy = `
import os, select, subprocess, sys, time

proc = subprocess.Popen(sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
out = b""
deadline = time.monotonic() + 60
next_probe = 0
ready = False
while True:
    now = time.monotonic()
    if now > deadline:
        proc.kill()
        sys.stdout.buffer.write(out)
        sys.exit(124)
    if not ready and now >= next_probe:
        proc.stdin.write(b"echo vmtest-ready-$((40+2))\n")
        proc.stdin.flush()
        next_probe = now + 1
    if select.select([proc.stdout], [], [], 0.1)[0]:
        data = os.read(proc.stdout.fileno(), 4096)
        if not data:
            break
        out += data
        if not ready and b"vmtest-ready-42" in out:
            ready = True
            proc.stdin.write(os.environ["VMTEST_PTY_INPUT"].encode() + b"\n")
            proc.stdin.flush()
sys.stdout.buffer.write(out)
sys.exit(proc.wait())
`

// testPTY tests sessions with a pty, both an interactive login shell typed
// into via stdin and a command run with a pty.
func (st *sshTest) testPTY(t *testing.T) {
	// The arithmetic makes the command's output differ from the pty's echo
	// of the typed command.
	out, code := st.run(t, "cat >/tmp/vmtest-pty.py <<'EOF'"+ptyDriverPy+"EOF\n"+
		`VMTEST_PTY_INPUT=$(printf 'tty\necho pty-$((6*7))\nexit 3\n') python3 /tmp/vmtest-pty.py `+st.sshCmd("tsuser", "-tt"))
	// TODO: require exit status 3. Tailscale SSH runs interactive shells
	// with a pty under login(1), and both util-linux's and FreeBSD's login
	// exit 0 regardless of the shell's exit status, whereas OpenSSH's sshd
	// passes it through.
	switch code {
	case 3:
	case 124:
		t.Fatalf("interactive shell timed out; output:\n%s", out)
	default:
		t.Logf("KNOWN BUG: interactive shell exited %d, want 3", code)
	}
	checkContains(t, "interactive shell", out, "/dev/pts/", "pty-42")

	// With a pty, the command's stderr goes to the pty, which ssh writes to
	// its stdout, so discard ssh's own stderr.
	out, code = st.run(t, "timeout 60 "+st.sshCmd("tsuser", "-tt")+" "+shell.Quote("tty; echo pty-stderr-$((6*7)) >&2; exit 5")+" 2>/dev/null")
	if code != 5 {
		t.Errorf("command with pty exited %d, want 5; output:\n%s", code, out)
	}
	checkContains(t, "command with pty", out, "/dev/pts/", "pty-stderr-42")
}

// testExitCodes tests that the remote command's exit code is the ssh client's.
func (st *sshTest) testExitCodes(t *testing.T) {
	for _, tc := range []struct {
		cmd  string
		want int
	}{
		{"true", 0},
		{"exit 42", 42},
		{"vmtest-no-such-command", 127},
	} {
		if out, code := st.ssh(t, "tsuser", tc.cmd); code != tc.want {
			t.Errorf("ssh %q exited %d, want %d; output:\n%s", tc.cmd, code, tc.want, out)
		}
	}
}

// lastLines returns the last n lines of s, failing the test if it has fewer.
func lastLines(t *testing.T, s string, n int) []string {
	t.Helper()
	lines := strings.Split(s, "\n")
	if len(lines) < n {
		t.Fatalf("want at least %d lines of output; got:\n%s", n, s)
	}
	return lines[len(lines)-n:]
}

// testSFTP tests uploading and downloading with the OpenSSH sftp client
// in batch mode, as a non-root user.
func (st *sshTest) testSFTP(t *testing.T) {
	dlSum := st.mustSSH(t, "tsuser", "head -c 300000 /dev/urandom >sftp-dl.bin && cksum <sftp-dl.bin")

	out := st.mustRun(t, `set -e
rm -rf /tmp/vmtest-sftp
mkdir /tmp/vmtest-sftp
cd /tmp/vmtest-sftp
head -c 400000 /dev/urandom >up.bin
printf 'put up.bin sftp-up.bin\nget sftp-dl.bin dl.bin\n' >batch
sftp -b batch `+strings.TrimSpace(sshOpts)+" "+st.dest("tsuser")+` >/dev/null
cksum <up.bin
cksum <dl.bin`)
	sums := lastLines(t, out, 2)
	upSum, gotDLSum := sums[0], sums[1]
	if gotDLSum != dlSum {
		t.Errorf("downloaded file cksum = %q, want %q", gotDLSum, dlSum)
	}

	// find prints the name only if the user and group match.
	got := st.mustSSH(t, "tsuser", "cksum <sftp-up.bin && find sftp-up.bin -user tsuser -group tsuser")
	if want := upSum + "\nsftp-up.bin"; got != want {
		t.Errorf("uploaded file cksum and owner = %q, want %q", got, want)
	}
}

// testSCP tests uploading and downloading with the OpenSSH scp client, using
// both its default SFTP protocol and its legacy scp protocol, as a non-root
// user.
func (st *sshTest) testSCP(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag string
	}{
		{"SFTPProtocol", ""},
		{"LegacyProtocol", "-O"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dlSum := st.mustSSH(t, "tsuser", "head -c 300000 /dev/urandom >scp-dl.bin && cksum <scp-dl.bin")
			scp := "scp -q " + tc.flag + sshOpts
			out := st.mustRun(t, `set -e
rm -rf /tmp/vmtest-scp
mkdir /tmp/vmtest-scp
cd /tmp/vmtest-scp
head -c 400000 /dev/urandom >up.bin
`+scp+" up.bin "+st.dest("tsuser")+`:scp-up.bin
`+scp+" "+st.dest("tsuser")+`:scp-dl.bin dl.bin
cksum <up.bin
cksum <dl.bin`)
			sums := lastLines(t, out, 2)
			upSum, gotDLSum := sums[0], sums[1]
			if gotDLSum != dlSum {
				t.Errorf("downloaded file cksum = %q, want %q", gotDLSum, dlSum)
			}
			got := st.mustSSH(t, "tsuser", "cksum <scp-up.bin && find scp-up.bin -user tsuser -group tsuser && rm scp-up.bin")
			if want := upSum + "\nscp-up.bin"; got != want {
				t.Errorf("uploaded file cksum and owner = %q, want %q", got, want)
			}
		})
	}
}

// testAgentForwarding tests "ssh -A": the key in an ssh-agent on the client
// is listed by ssh-add on the server, if the policy permits agent forwarding.
func (st *sshTest) testAgentForwarding(t *testing.T) {
	// The script prints the key's fingerprint and then runs "ssh-add -l" on
	// the server, exiting with its exit code.
	script := `set -e
rm -f /tmp/vmtest-agentkey /tmp/vmtest-agentkey.pub
ssh-keygen -q -t ed25519 -N '' -C vmtest-agent-key -f /tmp/vmtest-agentkey
eval "$(ssh-agent -s)" >/dev/null
trap 'ssh-agent -k >/dev/null' EXIT
ssh-add -q /tmp/vmtest-agentkey
echo "fingerprint=$(ssh-keygen -lf /tmp/vmtest-agentkey.pub | cut -d' ' -f2)"
set +e
` + st.sshCmd("tsuser", "-A") + " 'ssh-add -l'"

	out, code := st.run(t, script)
	if code != 0 {
		t.Fatalf("ssh -A ... ssh-add -l exited %d:\n%s", code, out)
	}
	_, fp, ok := strings.Cut(out, "fingerprint=")
	if !ok {
		t.Fatalf("no fingerprint in output:\n%s", out)
	}
	fp, _, _ = strings.Cut(fp, "\n")
	checkContains(t, "ssh-add -l on server", out, fp+" vmtest-agent-key")

	t.Run("NotPermitted", func(t *testing.T) {
		st.withPolicy(t, acceptPolicy(map[string]string{"*": "="}, &tailcfg.SSHAction{Accept: true}))
		// ssh-add exits 2 if it can't connect to an agent.
		if out, code := st.run(t, script); code != 2 {
			t.Errorf("ssh -A ... ssh-add -l with agent forwarding not permitted exited %d, want 2:\n%s", code, out)
		}
	})
}

// testAcceptEnv tests that "ssh -o SendEnv" delivers variables the policy's
// AcceptEnv permits, and only those.
func (st *sshTest) testAcceptEnv(t *testing.T) {
	out := st.mustRun(t, "VMTEST_ACCEPTED=yes VMTEST_REJECTED=no "+
		st.sshCmd("tsuser", "-o SendEnv=VMTEST_ACCEPTED", "-o SendEnv=VMTEST_REJECTED")+
		" "+shell.Quote(`echo "accepted=${VMTEST_ACCEPTED-unset} rejected=${VMTEST_REJECTED-unset}"`))
	if want := "accepted=yes rejected=unset"; out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// largeTransferTimeout bounds each direction of [sshTest.testLargeTransfer].
// The transfers normally take a few seconds; the bound is generous to avoid
// flakes on loaded CI machines while still catching stalls.
const largeTransferTimeout = 90 * time.Second

// testLargeTransfer pipes 64 MiB through an SSH session in each direction.
func (st *sshTest) testLargeTransfer(t *testing.T) {
	const size = 64 << 20
	for _, tc := range []struct {
		name   string
		script string
	}{
		{"Upload", fmt.Sprintf("head -c %d /dev/zero | %s 'wc -c'", size, st.sshCmd("tsuser"))},
		{"Download", fmt.Sprintf("%s 'head -c %d /dev/zero' | wc -c", st.sshCmd("tsuser"), size)},
	} {
		start := time.Now()
		out := st.mustRun(t, tc.script)
		d := time.Since(start)
		if got := strings.TrimSpace(out); got != strconv.Itoa(size) {
			t.Errorf("%s: got %q bytes, want %d", tc.name, got, size)
		}
		t.Logf("%s: %d bytes in %v (%.1f MB/s)", tc.name, size, d.Round(time.Millisecond), float64(size)/1e6/d.Seconds())
		if d > largeTransferTimeout {
			t.Errorf("%s took %v, want at most %v", tc.name, d, largeTransferTimeout)
		}
	}
}

// testControlMaster tests multiple concurrent session channels on one SSH
// connection, using OpenSSH connection multiplexing.
func (st *sshTest) testControlMaster(t *testing.T) {
	const ctl = "-o ControlPath=/tmp/vmtest-mux.sock"
	st.mustRun(t, "rm -f /tmp/vmtest-mux.sock\n"+
		st.sshCmd("tsuser", ctl, "-o ControlMaster=yes", "-o ControlPersist=120", "-f", "-N")+" </dev/null >/dev/null 2>&1")
	t.Cleanup(func() { st.run(t, st.sshCmd("tsuser", ctl, "-O exit")) })

	out := st.mustRun(t, st.sshCmd("tsuser", ctl, "-O check"))
	checkContains(t, "ssh -O check", out, "Master running")

	// Each session creates a file and then waits for all sessions' files to
	// exist, so they only all succeed if they run concurrently.
	const numSessions = 4
	st.mustSSH(t, "tsuser", "rm -rf /tmp/vmtest-mux && mkdir /tmp/vmtest-mux")
	var script strings.Builder
	for i := range numSessions {
		remote := fmt.Sprintf("touch /tmp/vmtest-mux/%d; n=0; "+
			"while [ $(ls /tmp/vmtest-mux | wc -l) -lt %d ]; do "+
			"n=$((n+1)); if [ $n -gt 300 ]; then echo mux-%d-timeout; exit 1; fi; sleep 0.1; "+
			"done; echo mux-%d-ok", i, numSessions, i, i)
		fmt.Fprintf(&script, "%s %s >/tmp/vmtest-mux.%d.out 2>&1 &\n",
			st.sshCmd("tsuser", ctl, "-o ControlMaster=no"), shell.Quote(remote), i)
	}
	script.WriteString("wait\ncat /tmp/vmtest-mux.*.out\n")
	out = st.mustRun(t, script.String())
	for i := range numSessions {
		checkContains(t, "multiplexed sessions", out, fmt.Sprintf("mux-%d-ok", i))
	}

	// All the sessions went over the master's one TCP connection.
	out = st.mustRun(t, "ss -Htn state established dst "+st.serverIP.String()+":22 | wc -l")
	if out != "1" {
		t.Errorf("%s TCP connections to the server's SSH port, want 1", out)
	}
}

// pollCurl is a shell fragment that fetches $url, retrying for up to about
// 10 seconds while the forwarding it goes through is set up.
const pollCurl = `ok=1
for i in $(seq 100); do
	if curl -sf "$url"; then ok=0; break; fi
	sleep 0.1
done`

// testLocalPortForwarding tests "ssh -L" to a TCP listener on the server's
// loopback interface, and that "ssh -W" (which uses the same channel type)
// is refused when the policy doesn't permit local port forwarding.
func (st *sshTest) testLocalPortForwarding(t *testing.T) {
	st.serverExec(t, "mkdir -p /tmp/vmtest-lfwd && echo local-forward-ok >/tmp/vmtest-lfwd/fwd.txt && "+
		"(setsid python3 -m http.server 18123 --bind 127.0.0.1 --directory /tmp/vmtest-lfwd </dev/null >/dev/null 2>&1 &)")
	t.Cleanup(func() { st.env.SSHExec(st.server, "pkill -f '[h]ttp.server 18123'") })

	out := st.mustRun(t, st.sshCmd("tsuser", "-N", "-o ExitOnForwardFailure=yes", "-L 127.0.0.1:19123:127.0.0.1:18123")+
		" </dev/null >/dev/null 2>&1 &\n"+
		"pid=$!\n"+
		"url=http://127.0.0.1:19123/fwd.txt\n"+
		pollCurl+"\n"+
		"kill $pid\n"+
		"exit $ok")
	if out != "local-forward-ok" {
		t.Errorf("fetch through ssh -L = %q, want %q", out, "local-forward-ok")
	}

	t.Run("NotPermitted", func(t *testing.T) {
		st.withPolicy(t, acceptPolicy(map[string]string{"*": "="}, &tailcfg.SSHAction{Accept: true}))
		out, code := st.run(t, `printf 'GET /fwd.txt HTTP/1.0\r\n\r\n' | `+st.sshCmd("tsuser", "-W 127.0.0.1:18123"))
		if code == 0 || strings.Contains(out, "local-forward-ok") {
			t.Errorf("ssh -W with local port forwarding not permitted: exit %d, want failure; output:\n%s", code, out)
		}
	})
}

// testRemotePortForwarding tests "ssh -R" from the server's loopback
// interface to a TCP listener on the client's, and that it's refused when the
// policy doesn't permit remote port forwarding.
func (st *sshTest) testRemotePortForwarding(t *testing.T) {
	st.mustRun(t, "mkdir -p /tmp/vmtest-rfwd && echo remote-forward-ok >/tmp/vmtest-rfwd/fwd.txt && "+
		"(setsid python3 -m http.server 18124 --bind 127.0.0.1 --directory /tmp/vmtest-rfwd </dev/null >/dev/null 2>&1 &)")
	t.Cleanup(func() { st.run(t, "pkill -f '[h]ttp.server 18124'") })

	remote := "url=http://127.0.0.1:19124/fwd.txt\n" + pollCurl + "\nexit $ok"
	fwd := []string{"-o ExitOnForwardFailure=yes", "-R 127.0.0.1:19124:127.0.0.1:18124"}
	out := st.mustRun(t, st.sshCmd("tsuser", fwd...)+" "+shell.Quote(remote))
	if out != "remote-forward-ok" {
		t.Errorf("fetch through ssh -R = %q, want %q", out, "remote-forward-ok")
	}

	t.Run("NotPermitted", func(t *testing.T) {
		st.withPolicy(t, acceptPolicy(map[string]string{"*": "="}, &tailcfg.SSHAction{Accept: true}))
		out, code := st.run(t, st.sshCmd("tsuser", fwd...)+" 'sleep 10; echo session-finished'")
		if code != 255 || strings.Contains(out, "session-finished") {
			t.Errorf("ssh -R with remote port forwarding not permitted: exit %d, want 255 before the session finishes; output:\n%s", code, out)
		}
		checkContains(t, "ssh -R not permitted", out, "remote port forwarding failed")
	})
}

// testTailscaleSSHCommand tests the "tailscale ssh" CLI wrapper on the client,
// which runs OpenSSH with a ProxyCommand of "tailscale nc" and strict host key
// checking against a known_hosts file it generates from the netmap.
func (st *sshTest) testTailscaleSSHCommand(t *testing.T) {
	shortName, _, _ := strings.Cut(st.serverDNSName, ".")
	for _, host := range []string{shortName, strings.TrimSuffix(st.serverDNSName, ".")} {
		out := st.mustRun(t, "tailscale ssh tsuser@"+host+" id -un")
		if out != "tsuser" {
			t.Errorf("tailscale ssh tsuser@%s id -un = %q, want %q", host, out, "tsuser")
		}
	}

	// Tailscale SSH on Ubuntu serves the system's host keys, which the
	// server advertised in its Hostinfo for "tailscale ssh" to trust.
	hostKey := st.serverExec(t, "cut -d' ' -f1,2 /etc/ssh/ssh_host_ed25519_key.pub")
	knownHosts := st.mustRun(t, "cat /root/.config/tailscale/ssh_known_hosts")
	checkContains(t, "tailscale ssh known_hosts", knownHosts,
		st.serverDNSName+" "+hostKey+"\n",
		st.serverIP.String()+" "+hostKey+"\n")
}

// testBanners tests that the OpenSSH client shows the Message of the policy's
// Accept and Reject actions.
func (st *sshTest) testBanners(t *testing.T) {
	// OpenSSH only shows auth banners at LogLevel INFO or above.
	const logInfo = "-o LogLevel=INFO"
	everyone := map[string]string{"*": "="}

	t.Run("Accept", func(t *testing.T) {
		st.withPolicy(t, acceptPolicy(everyone, &tailcfg.SSHAction{Accept: true, Message: "vmtest-accept-banner\n"}))
		out, code := st.run(t, st.sshCmd("tsuser", logInfo)+" 'echo session-ran'")
		if code != 0 {
			t.Fatalf("ssh exited %d:\n%s", code, out)
		}
		checkContains(t, "accept banner", out, "vmtest-accept-banner", "session-ran")
	})
	t.Run("Reject", func(t *testing.T) {
		st.withPolicy(t, acceptPolicy(everyone, &tailcfg.SSHAction{Reject: true, Message: "vmtest-reject-banner\n"}))
		out, code := st.run(t, st.sshCmd("tsuser", logInfo)+" 'echo session-ran'")
		if code != 255 || strings.Contains(out, "session-ran") {
			t.Errorf("ssh exited %d, want 255 without running the session; output:\n%s", code, out)
		}
		checkContains(t, "reject banner", out, "vmtest-reject-banner")
	})
}

// testUserMapping tests the policy's mapping of SSH user names to local users.
func (st *sshTest) testUserMapping(t *testing.T) {
	st.withPolicy(t, acceptPolicy(map[string]string{
		"alice":  "tsuser",
		"tsuser": "=",
	}, &tailcfg.SSHAction{Accept: true}))

	st.check(t, "alice maps to tsuser", "alice", "id -un && pwd", "tsuser\n/home/tsuser")
	st.check(t, "tsuser maps to itself", "tsuser", "id -un", "tsuser")
	for _, user := range []string{"carol", "root"} {
		out, code := st.run(t, st.sshCmd(user, "-o LogLevel=INFO")+" 'echo session-ran'")
		if code != 255 || strings.Contains(out, "session-ran") {
			t.Errorf("unmapped user %q: ssh exited %d, want 255 without running the session; output:\n%s", user, code, out)
		}
		checkContains(t, "unmapped user "+user, out, "tailnet policy does not permit you to SSH")
	}
}

// testRevokeActiveSession tests that a policy change revoking a user's
// access terminates that user's established sessions, with and without a pty,
// killing their processes.
func (st *sshTest) testRevokeActiveSession(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
		sleep string // distinctive, so pgrep only finds this session's process
	}{
		{"NoPTY", nil, "sleep 607"},
		{"PTY", []string{"-tt"}, "sleep 608"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The brackets keep pkill from matching the shell running it.
			pattern := "'[" + tc.sleep[:1] + "]" + tc.sleep[1:] + "'"
			t.Cleanup(func() {
				st.run(t, "pkill -f "+pattern)
				st.env.SSHExec(st.server, "pkill -f "+pattern)
			})
			pgrep := "pgrep -u tsuser -f " + pattern
			bgName := "revoke-" + tc.name

			st.startBackground(t, bgName, st.sshCmd("tsuser", tc.flags...)+" '"+tc.sleep+"'")
			if err := tstest.WaitFor(30*time.Second, func() error {
				_, err := st.env.SSHExec(st.server, pgrep)
				return err
			}); err != nil {
				out, _ := st.backgroundOutput(t, bgName)
				t.Fatalf("remote %q never started: %v; ssh output:\n%s", tc.sleep, err, out)
			}

			st.withPolicy(t, acceptPolicy(map[string]string{"root": "root"}, &tailcfg.SSHAction{Accept: true}))

			out, code := st.waitBackground(t, bgName, 30*time.Second)
			if code != 255 {
				t.Errorf("ssh exited %d after its access was revoked, want 255; output:\n%s", code, out)
			}
			// TODO: require the "Access revoked." message. tailssh writes it
			// to the session's stderr asynchronously and closes the
			// connection right away, so the client rarely gets it.
			if !strings.Contains(out, "Access revoked") {
				t.Logf("KNOWN BUG: no revocation message in ssh output:\n%s", out)
			}

			// TODO: make this an error. The session's processes survive
			// revocation: su -c runs the command in a new session
			// (setsid), out of reach of the SIGHUP and SIGKILL that
			// tailssh sends the session's process group, and on a pty
			// it's no longer in the pty's session either.
			if err := tstest.WaitFor(10*time.Second, func() error {
				if out, err := st.env.SSHExec(st.server, pgrep); err == nil {
					return fmt.Errorf("remote process still running: pid %s", strings.TrimSpace(out))
				}
				return nil
			}); err != nil {
				t.Logf("KNOWN BUG: after revocation: %v", err)
			}
		})
	}
}

// testCheckMode tests the HoldAndDelegate ("check mode") flow end to end:
// tailssh shows the action's Message, fetches the delegate URL (with its
// variables expanded) from the control server over Noise, and then applies
// the action the control server returns.
func (st *sshTest) testCheckMode(t *testing.T) {
	cs := st.env.ControlServer()

	// hold is a delegate URL fetch awaiting the test's verdict.
	type hold struct {
		uri     string
		verdict chan<- *tailcfg.SSHAction
	}
	holds := make(chan hold)
	done := make(chan struct{})
	cs.SetMachineSSHHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verdict := make(chan *tailcfg.SSHAction, 1)
		select {
		case holds <- hold{r.URL.RequestURI(), verdict}:
		case <-done:
			http.Error(w, "test over", http.StatusServiceUnavailable)
			return
		case <-r.Context().Done():
			return
		}
		select {
		case a := <-verdict:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(a)
		case <-done:
			http.Error(w, "test over", http.StatusServiceUnavailable)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(done)
		cs.SetMachineSSHHandler(nil)
		st.run(t, "pkill -f '[v]mtest-check-mode'")
	})

	st.withPolicy(t, acceptPolicy(map[string]string{"*": "="}, &tailcfg.SSHAction{
		Message:         "vmtest-check-pending\n",
		HoldAndDelegate: "https://unused/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?ssh_user=$SSH_USER&local_user=$LOCAL_USER&src_ip=$SRC_NODE_IP",
	}))

	// awaitHold starts ssh in the background and waits for its delegate URL
	// fetch, checking that the client is shown the hold message and is
	// still waiting.
	awaitHold := func(t *testing.T, name string) hold {
		t.Helper()
		st.startBackground(t, name, st.sshCmd("tsuser", "-o LogLevel=INFO")+" 'echo vmtest-check-mode; id -un'")
		var h hold
		select {
		case h = <-holds:
		case <-time.After(30 * time.Second):
			out, _ := st.backgroundOutput(t, name)
			t.Fatalf("no delegate URL fetch; ssh output:\n%s", out)
		}
		t.Logf("delegate URL fetch: %s", h.uri)
		if !strings.HasPrefix(h.uri, "/machine/ssh/action/") {
			t.Errorf("delegate URL path = %q, want /machine/ssh/action/ prefix", h.uri)
		}
		checkContains(t, "delegate URL", h.uri, "ssh_user=tsuser", "local_user=tsuser", "src_ip="+st.clientIP.String())

		if err := tstest.WaitFor(30*time.Second, func() error {
			out, exited := st.backgroundOutput(t, name)
			if exited {
				return fmt.Errorf("ssh exited while held; output:\n%s", out)
			}
			if !strings.Contains(out, "vmtest-check-pending") {
				return fmt.Errorf("hold message not shown; output:\n%s", out)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return h
	}

	t.Run("Approve", func(t *testing.T) {
		h := awaitHold(t, "check-approve")
		h.verdict <- &tailcfg.SSHAction{Accept: true}
		out, code := st.waitBackground(t, "check-approve", 30*time.Second)
		if code != 0 {
			t.Fatalf("ssh exited %d after approval:\n%s", code, out)
		}
		checkContains(t, "approved session", out, "vmtest-check-mode\ntsuser")
	})
	t.Run("Deny", func(t *testing.T) {
		h := awaitHold(t, "check-deny")
		h.verdict <- &tailcfg.SSHAction{Reject: true, Message: "vmtest-check-denied\n"}
		out, code := st.waitBackground(t, "check-deny", 30*time.Second)
		if code != 255 || strings.Contains(out, "tsuser") {
			t.Errorf("ssh exited %d after denial, want 255 without running the session; output:\n%s", code, out)
		}
		checkContains(t, "denied session", out, "vmtest-check-denied")
	})
}

// recorderPy is a minimal session recorder speaking the legacy /record
// protocol of [tailscale.com/sessionrecording]: it accepts a chunked POST
// after a 100 Continue response, writing the body to a new file in the output
// directory as it arrives. It doesn't speak HTTP/2, so tailssh's probe for the
// /v2/record endpoint fails and it falls back to /record.
const recorderPy = `
import http.server, itertools, os, sys

port, outdir = int(sys.argv[1]), sys.argv[2]
os.makedirs(outdir, exist_ok=True)
seq = itertools.count()

class Recorder(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        if self.path != "/record":
            self.send_error(404)
            return
        with open(os.path.join(outdir, "%d.cast" % next(seq)), "wb") as f:
            while True:
                size = int(self.rfile.readline().split(b";")[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                f.write(self.rfile.read(size))
                f.flush()
                self.rfile.readline()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

http.server.ThreadingHTTPServer(("0.0.0.0", port), Recorder).serve_forever()
`

// testRecording tests session recording to a recorder on the client node,
// and the OnRecordingFailure behavior when no recorder is reachable.
func (st *sshTest) testRecording(t *testing.T) {
	const port = 8199
	st.mustRun(t, "cat >/tmp/vmtest-recorder.py <<'EOF'"+recorderPy+"EOF\n"+
		"rm -rf /tmp/vmtest-rec\n"+
		fmt.Sprintf("(setsid python3 /tmp/vmtest-recorder.py %d /tmp/vmtest-rec </dev/null >/tmp/vmtest-recorder.log 2>&1 &)", port))
	t.Cleanup(func() { st.run(t, "pkill -f '[v]mtest-recorder.py'") })
	if err := tstest.WaitFor(30*time.Second, func() error {
		// The recorder answers GET with an error, which curl without -f
		// doesn't mind.
		if out, code := st.run(t, fmt.Sprintf("curl -s -o /dev/null http://127.0.0.1:%d/", port)); code != 0 {
			return fmt.Errorf("recorder not up: exit %d: %s", code, out)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	recorder := netip.AddrPortFrom(st.clientIP, port)
	noRecorder := netip.AddrPortFrom(st.clientIP, port-1) // nothing listens here
	const rejectMsg = "vmtest-recording-unavailable"
	recordingPolicy := func(rec netip.AddrPort, onFailure *tailcfg.SSHRecorderFailureAction) *tailcfg.SSHPolicy {
		return acceptPolicy(map[string]string{"*": "="}, &tailcfg.SSHAction{
			Accept:             true,
			Recorders:          []netip.AddrPort{rec},
			OnRecordingFailure: onFailure,
		})
	}

	t.Run("Recorded", func(t *testing.T) {
		st.withPolicy(t, recordingPolicy(recorder, &tailcfg.SSHRecorderFailureAction{RejectSessionWithMessage: rejectMsg}))
		// The arithmetic makes the session's output differ from its
		// command, which the recording's header also includes.
		if out := st.mustSSH(t, "tsuser", "echo rec-$((40+2))"); out != "rec-42" {
			t.Errorf("recorded session output = %q, want %q", out, "rec-42")
		}
		if err := tstest.WaitFor(30*time.Second, func() error {
			out, _ := st.run(t, "cat /tmp/vmtest-rec/*.cast")
			if !strings.Contains(out, "rec-42") {
				return fmt.Errorf("session output not in recordings:\n%s", out)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	t.Run("RejectWithoutRecorder", func(t *testing.T) {
		st.withPolicy(t, recordingPolicy(noRecorder, &tailcfg.SSHRecorderFailureAction{RejectSessionWithMessage: rejectMsg}))
		out, code := st.ssh(t, "tsuser", "echo session-ran")
		// tailssh exits 254 when it refuses a session for want of a recorder.
		if code != 254 || strings.Contains(out, "session-ran") {
			t.Errorf("ssh exited %d, want 254 without running the session; output:\n%s", code, out)
		}
		checkContains(t, "rejected session", out, rejectMsg)
	})
	t.Run("FailOpenWithoutRecorder", func(t *testing.T) {
		st.withPolicy(t, recordingPolicy(noRecorder, nil))
		if out := st.mustSSH(t, "tsuser", "echo session-ran"); out != "session-ran" {
			t.Errorf("fail-open session output = %q, want %q", out, "session-ran")
		}
	})
}
