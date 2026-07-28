// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/creachadair/mds/shell"
	"github.com/kdomanski/iso9660"
	"golang.org/x/crypto/ssh"
	"tailscale.com/tstest/natlab/vnet"
)

// createCloudInitISO creates a cidata seed ISO for the given cloud VM node.
// For Linux VMs, the ISO contains meta-data, user-data, and network-config.
// For FreeBSD VMs, the ISO contains meta-data and user-data only (nuageinit
// doesn't use netplan-style network-config; DHCP is enabled in rc.conf).
func (e *Env) createCloudInitISO(n *Node) (string, error) {
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", n.name, n.name)
	if err := ensureDebugSSHKey(); err != nil {
		return "", err
	}
	userData := e.generateUserData(n)

	files := map[string]string{
		"meta-data": metaData,
		"user-data": userData,
	}

	// Linux cloud-init needs network-config to configure interfaces before
	// systemd-networkd-wait-online blocks boot.
	if n.os.GOOS() == "linux" {
		files["network-config"] = `version: 2
ethernets:
  primary:
    match:
      macaddress: "` + n.vnetNode.NICMac(0).String() + `"
    dhcp4: true
    dhcp4-overrides:
      route-metric: 100
    optional: true
  secondary:
    match:
      name: "en*"
    dhcp4: true
    dhcp4-overrides:
      route-metric: 200
    optional: true
`
	}

	iw, err := iso9660.NewWriter()
	if err != nil {
		return "", fmt.Errorf("creating ISO writer: %w", err)
	}
	defer iw.Cleanup()

	for name, content := range files {
		if err := iw.AddFile(strings.NewReader(content), name); err != nil {
			return "", fmt.Errorf("adding %s to ISO: %w", name, err)
		}
	}

	isoPath := filepath.Join(e.tempDir, n.name+"-seed.iso")
	f, err := os.Create(isoPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := iw.WriteTo(f, "cidata"); err != nil {
		return "", fmt.Errorf("writing seed ISO: %w", err)
	}
	return isoPath, nil
}

// generateUserData creates the cloud-init user-data (#cloud-config) for a node.
func (e *Env) generateUserData(n *Node) string {
	switch n.os.GOOS() {
	case "linux":
		return e.generateLinuxUserData(n)
	case "freebsd":
		return e.generateFreeBSDUserData(n)
	default:
		panic(fmt.Sprintf("unsupported GOOS %q for cloud-init user-data", n.os.GOOS()))
	}
}

// generateLinuxUserData creates Linux cloud-init user-data (#cloud-config) for a node.
func (e *Env) generateLinuxUserData(n *Node) string {
	var ud strings.Builder
	ud.WriteString("#cloud-config\n")

	// Enable root SSH login for debugging via the debug NIC.
	ud.WriteString("ssh_pwauth: true\n")
	ud.WriteString("disable_root: false\n")
	ud.WriteString("users:\n")
	ud.WriteString("  - name: root\n")
	ud.WriteString("    lock_passwd: false\n")
	ud.WriteString("    plain_text_passwd: root\n")
	// Also inject the host's SSH key if available.
	if pubkey, err := os.ReadFile("/tmp/vmtest_key.pub"); err == nil {
		ud.WriteString(fmt.Sprintf("    ssh_authorized_keys:\n      - %s\n", strings.TrimSpace(string(pubkey))))
	}

	if n.systemdUnit {
		e.writeSystemdUnitFiles(&ud, n)
	}

	ud.WriteString("runcmd:\n")

	// Remove the default route from the debug NIC (enp0s4) so traffic goes through vnet.
	// The debug NIC is only for SSH access from the host.
	ud.WriteString("  - [\"/bin/sh\", \"-c\", \"ip route del default via 10.0.2.2 dev enp0s4 2>/dev/null || true\"]\n")

	// Download binaries from the files.tailscale VIP (52.52.0.6).
	// Use the IP directly to avoid DNS resolution issues during early boot.
	binDir := n.os.GOOS() + "_" + n.os.GOARCH()
	for _, bin := range []string{"tailscaled", "tailscale", "tta"} {
		fmt.Fprintf(&ud, "  - [\"/bin/sh\", \"-c\", \"curl -v --retry 10 --retry-delay 2 --retry-all-errors -o /usr/local/bin/%s http://52.52.0.6/%s/%s 2>&1\"]\n", bin, binDir, bin)
	}
	ud.WriteString("  - [\"chmod\", \"+x\", \"/usr/local/bin/tailscaled\", \"/usr/local/bin/tailscale\", \"/usr/local/bin/tta\"]\n")

	// Apply the bin_t label for SELinux enforcement: we curl the binaries in
	// rather than installing a package, so nothing else labels them, and
	// enforcing mode would deny exec. No-op on non-SELinux systems, but only
	// RHEL-family images ship restorecon.
	if n.os.Family == LinuxRHEL {
		ud.WriteString("  - [\"/bin/sh\", \"-c\", \"restorecon -v /usr/local/bin/tailscaled /usr/local/bin/tailscale /usr/local/bin/tta 2>&1 || true\"]\n")
	}

	// Enable IP forwarding for subnet routers.
	if n.advertiseRoutes != "" {
		ud.WriteString("  - [\"sysctl\", \"-w\", \"net.ipv4.ip_forward=1\"]\n")
		ud.WriteString("  - [\"sysctl\", \"-w\", \"net.ipv6.conf.all.forwarding=1\"]\n")
	}

	// Provision the requested DNS backend before tailscaled starts.
	writeLinuxDNSModeSetup(&ud, n.dnsMode)

	// Start tailscaled, either via the stock systemd unit or directly in
	// the background. --statedir provides a VarRoot so features like
	// Taildrop (which needs a place to stash incoming files) have a
	// directory to work with.
	if n.systemdUnit {
		// The unit's ExecStart runs /usr/sbin/tailscaled.
		ud.WriteString("  - [\"cp\", \"/usr/local/bin/tailscaled\", \"/usr/sbin/tailscaled\"]\n")
		ud.WriteString("  - [\"systemctl\", \"daemon-reload\"]\n")
		// Type=notify makes this block until tailscaled reports readiness.
		ud.WriteString("  - [\"systemctl\", \"start\", \"tailscaled.service\"]\n")
	} else {
		ud.WriteString("  - [\"mkdir\", \"-p\", \"/var/lib/tailscale\"]\n")
		fmt.Fprintf(&ud, "  - [\"/bin/sh\", \"-c\", \"%s/usr/local/bin/tailscaled --state=mem: --statedir=/var/lib/tailscale &\"]\n", tailscaledEnvPrefix(n))
		ud.WriteString("  - [\"sleep\", \"2\"]\n")
	}

	// Start tta (Tailscale Test Agent).
	ud.WriteString("  - [\"/bin/sh\", \"-c\", \"/usr/local/bin/tta &\"]\n")

	return ud.String()
}

// writeLinuxDNSModeSetup appends cloud-init runcmd entries that provision the
// guest so tailscaled selects the requested DNS backend. Must run before the
// tailscaled launch entries. The zero value (DNSDefault) is a no-op. mode is
// validated in AddNode, so any other unknown value is a bug and panics.
func writeLinuxDNSModeSetup(ud *strings.Builder, mode DNSMode) {
	switch mode {
	default:
		// AddNode validates the mode, so an unknown value here is a bug.
		panic(fmt.Sprintf("unhandled DNSMode %q", mode))
	case DNSDefault:
		// The empty/zero value: leave the image's DNS config alone, so
		// systemd-resolved stays enabled and tailscaled selects it (or
		// whatever the image runs by default). No-op.
	case DNSDirect:
		// Mask systemd-resolved and drop a plain resolv.conf so dnsMode() in
		// net/dns/manager_linux.go falls through to "direct". Point it at
		// natlab's fake DNS VIP (not a public resolver): it's the only resolver
		// reachable in vnet and it serves the internal *.tailscale names.
		fmt.Fprintf(ud, "  - [\"/bin/sh\", \"-c\", \"systemctl disable --now systemd-resolved 2>/dev/null || true\"]\n")
		fmt.Fprintf(ud, "  - [\"/bin/sh\", \"-c\", \"systemctl mask systemd-resolved 2>/dev/null || true\"]\n")
		fmt.Fprintf(ud, "  - [\"/bin/sh\", \"-c\", \"rm -f /etc/resolv.conf && printf 'nameserver %s\\\\n' >/etc/resolv.conf\"]\n", vnet.FakeDNSIPv4())
	}
}

// generateFreeBSDUserData creates FreeBSD nuageinit user-data (#cloud-config)
// for a node. FreeBSD's nuageinit supports a subset of cloud-init directives
// including runcmd, which runs after networking is up.
//
// IMPORTANT: nuageinit's runcmd only supports string entries, not the YAML
// array form that Linux cloud-init supports. Each entry must be a plain string
// that gets passed to /bin/sh -c.
func (e *Env) generateFreeBSDUserData(n *Node) string {
	var ud strings.Builder
	ud.WriteString("#cloud-config\n")
	ud.WriteString("ssh_pwauth: true\n")

	ud.WriteString("runcmd:\n")

	// Enable root SSH login for debugging via the debug NIC.
	ud.WriteString("  - \"echo 'PermitRootLogin yes' >>/etc/ssh/sshd_config\"\n")
	ud.WriteString("  - \"echo 'PubkeyAuthentication yes' >>/etc/ssh/sshd_config\"\n")
	// Also inject the host's SSH key if available.
	if pubkey, err := os.ReadFile("/tmp/vmtest_key.pub"); err == nil {
		ud.WriteString("  - \"mkdir -p /root/.ssh && chmod 700 /root/.ssh\"\n")
		fmt.Fprintf(&ud, "  - \"echo '%s' >/root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys\"\n", strings.TrimSpace(string(pubkey)))
	}

	// /usr/local/bin may not exist on a fresh FreeBSD cloud image (it's
	// created when the first package is installed).
	ud.WriteString("  - \"mkdir -p /usr/local/bin\"\n")

	// Remove the default route via the debug NIC's SLIRP gateway so that
	// traffic goes through the vnet NICs. The debug NIC is only for SSH.
	ud.WriteString("  - \"route delete default 10.0.2.2 2>/dev/null || true\"\n")

	// Grow the TCP socket buffer limits before the binary downloads
	// below. FreeBSD's defaults start receive windows at 64 kB and
	// autoscale in slow 16 kB steps, which caps a transfer at roughly
	// 64kB per round trip. On an oversubscribed CI runner, where
	// scheduling delay inflates the effective RTT of the userspace vnet
	// data path to tens or hundreds of milliseconds, that works out to
	// a few hundred kB/s and made the multi-megabyte binary fetches (and
	// so the whole test) time out.
	ud.WriteString("  - \"sysctl kern.ipc.maxsockbuf=16777216\"\n")
	ud.WriteString("  - \"sysctl net.inet.tcp.recvspace=4194304\"\n")
	ud.WriteString("  - \"sysctl net.inet.tcp.sendspace=1048576\"\n")
	ud.WriteString("  - \"sysctl net.inet.tcp.recvbuf_max=16777216\"\n")
	ud.WriteString("  - \"sysctl net.inet.tcp.sendbuf_max=16777216\"\n")

	// Download binaries from the files.tailscale VIP (52.52.0.6).
	// FreeBSD's fetch(1) is part of the base system (no curl needed).
	// Retry in a loop since the file server may not be ready immediately.
	binDir := n.os.GOOS() + "_" + n.os.GOARCH()
	for _, bin := range []string{"tailscaled", "tailscale", "tta"} {
		fmt.Fprintf(&ud, "  - \"n=0; while [ $n -lt 10 ]; do fetch -o /usr/local/bin/%s http://52.52.0.6/%s/%s && break; n=$((n+1)); sleep 2; done\"\n", bin, binDir, bin)
	}
	ud.WriteString("  - \"chmod +x /usr/local/bin/tailscaled /usr/local/bin/tailscale /usr/local/bin/tta\"\n")

	// Enable IP forwarding for subnet routers.
	// This is currently a noop as of 2026-04-08 because FreeBSD uses
	// gvisor netstack for subnet routing until
	// https://github.com/tailscale/tailscale/issues/5573 etc are fixed.
	if n.advertiseRoutes != "" {
		ud.WriteString("  - \"sysctl net.inet.ip.forwarding=1\"\n")
		ud.WriteString("  - \"sysctl net.inet6.ip6.forwarding=1\"\n")
	}

	// Start tailscaled and tta in the background. Redirect stdio to log
	// files and away from /dev/null on stdin; otherwise nuageinit's runcmd
	// executor keeps the backgrounded child's stdout/stderr pipes open and
	// blocks waiting for them, so subsequent runcmd entries (including the
	// tta launch below) never run. Linux cloud-init doesn't have this
	// gotcha. Set PATH to include /usr/local/bin so that tta can find
	// "tailscale" (TTA uses exec.Command("tailscale", ...) without a full
	// path). --statedir provides a VarRoot so features like Taildrop have a
	// directory.
	ud.WriteString("  - \"mkdir -p /var/lib/tailscale\"\n")
	fmt.Fprintf(&ud, "  - \"export PATH=/usr/local/bin:$PATH && %s/usr/local/bin/tailscaled --state=mem: --statedir=/var/lib/tailscale </dev/null >/var/log/tailscaled.log 2>&1 &\"\n", tailscaledEnvPrefix(n))
	ud.WriteString("  - \"sleep 2\"\n")

	// Start tta (Tailscale Test Agent), with the same stdio redirection.
	ud.WriteString("  - \"export PATH=/usr/local/bin:$PATH && /usr/local/bin/tta </dev/null >/var/log/tta.log 2>&1 &\"\n")

	return ud.String()
}

// writeSystemdUnitFiles appends a cloud-init write_files section that
// installs the stock tailscaled systemd unit from the source tree, along
// with the packaging's /etc/default/tailscaled EnvironmentFile (plus any
// per-node TailscaledEnv variables). File contents are base64-encoded to
// sidestep YAML quoting.
func (e *Env) writeSystemdUnitFiles(ud *strings.Builder, n *Node) {
	modRoot, err := findModRoot()
	if err != nil {
		e.t.Fatalf("finding module root for tailscaled.service: %v", err)
	}
	unit, err := os.ReadFile(filepath.Join(modRoot, "cmd/tailscaled/tailscaled.service"))
	if err != nil {
		e.t.Fatalf("reading tailscaled.service: %v", err)
	}
	defaults, err := os.ReadFile(filepath.Join(modRoot, "cmd/tailscaled/tailscaled.defaults"))
	if err != nil {
		e.t.Fatalf("reading tailscaled.defaults: %v", err)
	}
	var envFile strings.Builder
	envFile.Write(defaults)
	for _, env := range n.vnetNode.Env() {
		fmt.Fprintf(&envFile, "%s=%q\n", env.Key, env.Value)
	}

	ud.WriteString("write_files:\n")
	writeFile := func(path string, content []byte) {
		fmt.Fprintf(ud, "  - path: %s\n", path)
		fmt.Fprintf(ud, "    encoding: b64\n")
		fmt.Fprintf(ud, "    content: %s\n", base64.StdEncoding.EncodeToString(content))
	}
	writeFile("/etc/systemd/system/tailscaled.service", unit)
	writeFile("/etc/default/tailscaled", []byte(envFile.String()))
}

func tailscaledEnvPrefix(n *Node) string {
	env := n.vnetNode.Env()
	if len(env) == 0 {
		return ""
	}
	parts := make([]string, 0, len(env))
	for _, e := range env {
		parts = append(parts, e.Key+"="+shell.Quote(e.Value))
	}
	sort.Strings(parts)
	return strings.Join(parts, " ") + " "
}

// debugSSHKeyMu serializes ensureDebugSSHKey calls. Env.Start boots all
// nodes in parallel and each calls createCloudInitISO -> ensureDebugSSHKey,
// which would otherwise race on creating /tmp/vmtest_key: one goroutine
// can observe a newly-created-but-still-empty key file written by another
// and fail to parse it.
var debugSSHKeyMu sync.Mutex

func ensureDebugSSHKey() error {
	debugSSHKeyMu.Lock()
	defer debugSSHKeyMu.Unlock()
	const keyPath = "/tmp/vmtest_key"
	if privPEM, err := os.ReadFile(keyPath); err == nil {
		if _, err := os.Stat(keyPath + ".pub"); err == nil {
			return nil
		}
		signer, err := ssh.ParsePrivateKey(privPEM)
		if err != nil {
			return fmt.Errorf("parse %s: %w", keyPath, err)
		}
		return os.WriteFile(keyPath+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0644)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "vmtest")
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600); err != nil {
		return err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return err
	}
	return os.WriteFile(keyPath+".pub", ssh.MarshalAuthorizedKey(sshPub), 0644)
}
