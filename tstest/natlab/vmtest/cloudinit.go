// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kdomanski/iso9660"
)

// createCloudInitISO creates a cidata seed ISO for the given cloud VM node.
// For Linux VMs, the ISO contains meta-data, user-data, and network-config.
// For FreeBSD VMs, the ISO contains meta-data and user-data only (nuageinit
// doesn't use netplan-style network-config; DHCP is enabled in rc.conf).
func (e *Env) createCloudInitISO(n *Node) (string, error) {
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", n.name, n.name)
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

	// Enable IP forwarding for subnet routers.
	if n.advertiseRoutes != "" {
		ud.WriteString("  - [\"sysctl\", \"-w\", \"net.ipv4.ip_forward=1\"]\n")
		ud.WriteString("  - [\"sysctl\", \"-w\", \"net.ipv6.conf.all.forwarding=1\"]\n")
	}

	// Start tailscaled in the background.
	ud.WriteString("  - [\"/bin/sh\", \"-c\", \"/usr/local/bin/tailscaled --state=mem: &\"]\n")
	ud.WriteString("  - [\"sleep\", \"2\"]\n")

	// Start tta (Tailscale Test Agent).
	ud.WriteString("  - [\"/bin/sh\", \"-c\", \"/usr/local/bin/tta &\"]\n")

	return ud.String()
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

	// /usr/local/bin may not exist on a fresh FreeBSD cloud image (it's
	// created when the first package is installed).
	ud.WriteString("  - \"mkdir -p /usr/local/bin\"\n")

	// Remove the default route via the debug NIC's SLIRP gateway so that
	// traffic goes through the vnet NICs. The debug NIC is only for SSH.
	ud.WriteString("  - \"route delete default 10.0.2.2 2>/dev/null || true\"\n")

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

	// Start tailscaled and tta in the background.
	// Set PATH to include /usr/local/bin so that tta can find "tailscale"
	// (TTA uses exec.Command("tailscale", ...) without a full path).
	ud.WriteString("  - \"export PATH=/usr/local/bin:$PATH && /usr/local/bin/tailscaled --state=mem: &\"\n")
	ud.WriteString("  - \"sleep 2\"\n")

	// Start tta (Tailscale Test Agent).
	ud.WriteString("  - \"export PATH=/usr/local/bin:$PATH && /usr/local/bin/tta &\"\n")

	return ud.String()
}
