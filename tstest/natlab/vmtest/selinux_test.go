// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/creachadair/mds/shell"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstest/natlab/vmtest"
	"tailscale.com/tstest/natlab/vnet"
)

// Guest paths for the resolv.conf label probe: the script, the labels it
// records, and its own stderr.
const (
	probePath    = "/root/resolvconf-label-probe.py"
	probeLogPath = "/root/resolvconf-label-probe.log"
	probeErrPath = "/root/resolvconf-label-probe.err"
)

// resolvConfLabelProbe watches /etc with inotify and, each time something
// is renamed to /etc/resolv.conf, records the SELinux label the new inode
// has at that instant. It wakes within microseconds of the rename, so it
// sees the file before any relabel that runs afterwards, the same way
// sssd_be does when it re-arms its watch (tailscale/tailscale#22418).
//
// Python is used because the Fedora cloud image has it (cloud-init needs
// it) and ships neither inotify-tools nor strace.
const resolvConfLabelProbe = `
import ctypes, os, struct, sys, time

IN_MOVED_TO = 0x80
libc = ctypes.CDLL(None, use_errno=True)
fd = libc.inotify_init1(0)
if fd < 0:
    raise OSError(ctypes.get_errno(), "inotify_init1")
if libc.inotify_add_watch(fd, b"/etc", IN_MOVED_TO) < 0:
    raise OSError(ctypes.get_errno(), "inotify_add_watch")
log = open(sys.argv[1], "a", buffering=1)
log.write("ready\n")
while True:
    buf = os.read(fd, 65536)
    off = 0
    while off < len(buf):
        _, mask, _, ln = struct.unpack_from("iIII", buf, off)
        name = buf[off+16:off+16+ln].rstrip(b"\0").decode()
        off += 16 + ln
        if name != "resolv.conf":
            continue
        try:
            label = os.getxattr("/etc/resolv.conf", "security.selinux").rstrip(b"\0").decode()
        except OSError as e:
            label = "error: %s" % e
        log.write("label %s\n" % label)
`

// TestDirectDNSSELinuxLabel checks that the direct DNS manager never leaves
// /etc/resolv.conf with the generic etc_t label, not even briefly. tailscaled
// writes the file as a temp file and renames it into place. On an
// SELinux-enforcing host, the temp file is created with the label of /etc,
// and rename(2) keeps the inode's label. Other confined services that watch
// the file (sssd_be, NetworkManager) are denied access to an etc_t
// resolv.conf, so the file must already be net_conf_t when the rename lands.
// A relabel after the rename is too late: it loses the race against anyone
// watching /etc with inotify. See tailscale/tailscale#20149 and #22418.
//
// The test runs on Fedora, which boots SELinux enforcing, with
// systemd-resolved masked so tailscaled uses the direct manager, and
// tailscaled under its stock systemd unit so it runs in the same SELinux
// domain as a package install. A probe in the guest records the label at
// each rename; toggling accept-dns drives the rewrites (off restores the
// backup, on writes a fresh file, so both rename paths are exercised).
func TestDirectDNSSELinuxLabel(t *testing.T) {
	// Without a DNS config from control there is nothing for the direct
	// manager to write, and toggling accept-dns would never touch the file.
	env := vmtest.New(t,
		vmtest.ControlDNS("tailnet.test", &tailcfg.DNSConfig{
			Proxied: true, // MagicDNS, so quad-100 is the nameserver written
		}))

	net := env.AddNetwork("2.1.1.1", "192.168.1.1/24", vnet.EasyNAT)
	node := env.AddNode("fedora", net,
		vmtest.OS(vmtest.Fedora43),
		vmtest.WithDNSMode(vmtest.DNSDirect),
		vmtest.SystemdUnit())

	env.Start()

	env.AssertDNSBackend(node, "direct")

	// On failure, show what the guest saw: the probe's own stderr, the
	// labels of every resolv.conf file, and tailscaled's DNS log lines.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, cmd := range []string{
			"cat " + probeErrPath,
			"ls -lZ /etc/resolv*",
			"journalctl -u tailscaled --no-pager -o cat | grep -i 'dns\\|resolv\\|restorecon' | tail -40",
			"journalctl -k --no-pager -o cat | grep avc | tail -20",
		} {
			out, err := env.SSHExec(node, cmd)
			t.Logf("# %s (err=%v)\n%s", cmd, err, out)
		}
	})

	// The whole point is enforcing mode. Permissive would still log the
	// probe's labels, but a pass would then say nothing about denials.
	out, err := env.SSHExec(node, "getenforce")
	if err != nil {
		t.Fatalf("getenforce: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(out); got != "Enforcing" {
		t.Fatalf("SELinux is %q, want Enforcing", got)
	}

	install := fmt.Sprintf("printf %%s %s > %s", shell.Quote(resolvConfLabelProbe), probePath)
	if out, err := env.SSHExec(node, install); err != nil {
		t.Fatalf("installing probe: %v\n%s", err, out)
	}
	// Detach fully from the SSH session: every fd of the probe is redirected
	// and only the probe itself is backgrounded, so the remote shell exits and
	// ssh sees EOF. Backgrounding a command list instead would leave a
	// subshell holding the session's pipes open.
	start := fmt.Sprintf("setsid python3 %s %s >%s 2>&1 </dev/null &", probePath, probeLogPath, probeErrPath)
	if out, err := env.SSHExec(node, start); err != nil {
		t.Fatalf("starting probe: %v\n%s", err, out)
	}
	if err := tstest.WaitFor(15*time.Second, func() error {
		out, err := env.SSHExec(node, "cat "+probeLogPath)
		if err != nil || !strings.Contains(out, "ready") {
			errOut, _ := env.SSHExec(node, "cat "+probeErrPath)
			return fmt.Errorf("probe not ready (%v): %s%s", err, out, errOut)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Each off/on toggle renames something to /etc/resolv.conf twice: off
	// renames the backup back into place, on renames the new temp file over
	// it. The probe records the label the renamed inode carried into place.
	const toggles = 10
	for range toggles {
		env.SetAcceptDNS(node, false)
		env.SetAcceptDNS(node, true)
	}
	wantEvents := 2 * toggles

	var labels []string
	if err := tstest.WaitFor(30*time.Second, func() error {
		out, err := env.SSHExec(node, "cat "+probeLogPath)
		if err != nil {
			return fmt.Errorf("reading probe log: %v\n%s", err, out)
		}
		labels = labels[:0]
		for _, line := range strings.Split(out, "\n") {
			if label, ok := strings.CutPrefix(line, "label "); ok {
				labels = append(labels, label)
			}
		}
		if len(labels) < wantEvents {
			return fmt.Errorf("probe saw %d renames to /etc/resolv.conf, want %d", len(labels), wantEvents)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	bad := 0
	for i, label := range labels {
		if !strings.Contains(label, ":net_conf_t:") {
			bad++
			t.Errorf("rename %d: /etc/resolv.conf appeared with label %q, want net_conf_t", i+1, label)
		}
	}
	t.Logf("probe saw %d renames to /etc/resolv.conf, %d with a wrong label", len(labels), bad)

	// The file must also end up correctly labelled once everything settles.
	out, err = env.SSHExec(node, "stat -c %C /etc/resolv.conf")
	if err != nil {
		t.Fatalf("stat: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(out); !strings.Contains(got, ":net_conf_t:") {
		t.Errorf("final /etc/resolv.conf label %q, want net_conf_t", got)
	}

	// No AVC denials against resolv.conf should have been logged. The cloud
	// image has no auditd, so denials go to the kernel log.
	if out, _ := env.SSHExec(node, "journalctl -k --no-pager -g 'avc:.*resolv.conf' -o cat"); strings.TrimSpace(out) != "" {
		t.Logf("AVC denials mentioning resolv.conf:\n%s", out)
	}
}
