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
// The ISO contains meta-data, user-data, and network-config files.
// Cloud-init reads these during init-local (pre-network), which is critical
// for network-config to take effect before systemd-networkd-wait-online runs.
func (e *Env) createCloudInitISO(n *Node) (string, error) {
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", n.name, n.name)
	userData := e.generateUserData(n)

	// Network config: DHCP all ethernet interfaces.
	// The "optional: true" prevents systemd-networkd-wait-online from blocking.
	// The first vnet NIC gets the default route (metric 100).
	// Other interfaces get higher metrics to avoid routing conflicts.
	networkConfig := `version: 2
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

	iw, err := iso9660.NewWriter()
	if err != nil {
		return "", fmt.Errorf("creating ISO writer: %w", err)
	}
	defer iw.Cleanup()

	for name, content := range map[string]string{
		"meta-data":      metaData,
		"user-data":      userData,
		"network-config": networkConfig,
	} {
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
	for _, bin := range []string{"tailscaled", "tailscale", "tta"} {
		fmt.Fprintf(&ud, "  - [\"/bin/sh\", \"-c\", \"curl -v --retry 10 --retry-delay 2 --retry-all-errors -o /usr/local/bin/%s http://52.52.0.6/%s 2>&1\"]\n", bin, bin)
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
