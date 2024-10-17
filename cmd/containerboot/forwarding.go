// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"tailscale.com/util/linuxfw"
)

// ensureIPForwarding enables IPv4/IPv6 forwarding for the container.
func ensureIPForwarding(root, clusterProxyTargetIP, tailnetTargetIP, tailnetTargetFQDN string, routes *string) error {
	var (
		v4Forwarding, v6Forwarding bool
	)
	if clusterProxyTargetIP != "" {
		proxyIP, err := netip.ParseAddr(clusterProxyTargetIP)
		if err != nil {
			return fmt.Errorf("invalid cluster destination IP: %v", err)
		}
		if proxyIP.Is4() {
			v4Forwarding = true
		} else {
			v6Forwarding = true
		}
	}
	if tailnetTargetIP != "" {
		proxyIP, err := netip.ParseAddr(tailnetTargetIP)
		if err != nil {
			return fmt.Errorf("invalid tailnet destination IP: %v", err)
		}
		if proxyIP.Is4() {
			v4Forwarding = true
		} else {
			v6Forwarding = true
		}
	}
	// Currently we only proxy traffic to the IPv4 address of the tailnet
	// target.
	if tailnetTargetFQDN != "" {
		v4Forwarding = true
	}
	if routes != nil && *routes != "" {
		for _, route := range strings.Split(*routes, ",") {
			cidr, err := netip.ParsePrefix(route)
			if err != nil {
				return fmt.Errorf("invalid subnet route: %v", err)
			}
			if cidr.Addr().Is4() {
				v4Forwarding = true
			} else {
				v6Forwarding = true
			}
		}
	}
	return enableIPForwarding(v4Forwarding, v6Forwarding, root)
}

func enableIPForwarding(v4Forwarding, v6Forwarding bool, root string) error {
	var paths []string
	if v4Forwarding {
		paths = append(paths, filepath.Join(root, "proc/sys/net/ipv4/ip_forward"))
	}
	if v6Forwarding {
		paths = append(paths, filepath.Join(root, "proc/sys/net/ipv6/conf/all/forwarding"))
	}

	// In some common configurations (e.g. default docker,
	// kubernetes), the container environment denies write access to
	// most sysctls, including IP forwarding controls. Check the
	// sysctl values before trying to change them, so that we
	// gracefully do nothing if the container's already been set up
	// properly by e.g. a k8s initContainer.
	for _, path := range paths {
		bs, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %q: %w", path, err)
		}
		if v := strings.TrimSpace(string(bs)); v != "1" {
			if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
				return fmt.Errorf("enabling %q: %w", path, err)
			}
		}
	}
	return nil
}

func installEgressForwardingRule(_ context.Context, dstStr string, tsIPs []netip.Prefix, nfr linuxfw.NetfilterRunner) error {
	dst, err := netip.ParseAddr(dstStr)
	if err != nil {
		return err
	}
	var local netip.Addr
	for _, pfx := range tsIPs {
		if !pfx.IsSingleIP() {
			continue
		}
		if pfx.Addr().Is4() != dst.Is4() {
			continue
		}
		local = pfx.Addr()
		break
	}
	if !local.IsValid() {
		return fmt.Errorf("no tailscale IP matching family of %s found in %v", dstStr, tsIPs)
	}
	if err := nfr.DNATNonTailscaleTraffic("tailscale0", dst); err != nil {
		return fmt.Errorf("installing egress proxy rules: %w", err)
	}
	if err := nfr.EnsureSNATForDst(local, dst); err != nil {
		return fmt.Errorf("installing egress proxy rules: %w", err)
	}
	if err := nfr.ClampMSSToPMTU("tailscale0", dst); err != nil {
		return fmt.Errorf("installing egress proxy rules: %w", err)
	}
	return nil
}

// installTSForwardingRuleForDestination accepts a destination address and a
// list of node's tailnet addresses, sets up rules to forward traffic for
// destination to the tailnet IP matching the destination IP family.
// Destination can be Pod IP of this node.
func installTSForwardingRuleForDestination(_ context.Context, dstFilter string, tsIPs []netip.Prefix, nfr linuxfw.NetfilterRunner) error {
	dst, err := netip.ParseAddr(dstFilter)
	if err != nil {
		return err
	}
	var local netip.Addr
	for _, pfx := range tsIPs {
		if !pfx.IsSingleIP() {
			continue
		}
		if pfx.Addr().Is4() != dst.Is4() {
			continue
		}
		local = pfx.Addr()
		break
	}
	if !local.IsValid() {
		return fmt.Errorf("no tailscale IP matching family of %s found in %v", dstFilter, tsIPs)
	}
	if err := nfr.AddDNATRule(dst, local); err != nil {
		return fmt.Errorf("installing rule for forwarding traffic to tailnet IP: %w", err)
	}
	return nil
}

func installIngressForwardingRule(_ context.Context, dstStr string, tsIPs []netip.Prefix, nfr linuxfw.NetfilterRunner) error {
	dst, err := netip.ParseAddr(dstStr)
	if err != nil {
		return err
	}
	var local netip.Addr
	proxyHasIPv4Address := false
	for _, pfx := range tsIPs {
		if !pfx.IsSingleIP() {
			continue
		}
		if pfx.Addr().Is4() {
			proxyHasIPv4Address = true
		}
		if pfx.Addr().Is4() != dst.Is4() {
			continue
		}
		local = pfx.Addr()
		break
	}
	if proxyHasIPv4Address && dst.Is6() {
		log.Printf("Warning: proxy backend ClusterIP is an IPv6 address and the proxy has a IPv4 tailnet address. You might need to disable IPv4 address allocation for the proxy for forwarding to work. See https://github.com/tailscale/tailscale/issues/12156")
	}
	if !local.IsValid() {
		return fmt.Errorf("no tailscale IP matching family of %s found in %v", dstStr, tsIPs)
	}
	if err := nfr.AddDNATRule(local, dst); err != nil {
		return fmt.Errorf("installing ingress proxy rules: %w", err)
	}
	if err := nfr.ClampMSSToPMTU("tailscale0", dst); err != nil {
		return fmt.Errorf("installing ingress proxy rules: %w", err)
	}
	return nil
}

func installIngressForwardingRuleForDNSTarget(_ context.Context, backendAddrs []net.IP, tsIPs []netip.Prefix, nfr linuxfw.NetfilterRunner) error {
	var (
		tsv4       netip.Addr
		tsv6       netip.Addr
		v4Backends []netip.Addr
		v6Backends []netip.Addr
	)
	for _, pfx := range tsIPs {
		if pfx.IsSingleIP() && pfx.Addr().Is4() {
			tsv4 = pfx.Addr()
			continue
		}
		if pfx.IsSingleIP() && pfx.Addr().Is6() {
			tsv6 = pfx.Addr()
			continue
		}
	}
	// TODO: log if more than one backend address is found and firewall is
	// in nftables mode that only the first IP will be used.
	for _, ip := range backendAddrs {
		if ip.To4() != nil {
			v4Backends = append(v4Backends, netip.AddrFrom4([4]byte(ip.To4())))
		}
		if ip.To16() != nil {
			v6Backends = append(v6Backends, netip.AddrFrom16([16]byte(ip.To16())))
		}
	}

	// Enable IP forwarding here as opposed to at the start of containerboot
	// as the IPv4/IPv6 requirements might have changed.
	// For Kubernetes operator proxies, forwarding for both IPv4 and IPv6 is
	// enabled by an init container, so in practice enabling forwarding here
	// is only needed if this proxy has been configured by manually setting
	// TS_EXPERIMENTAL_DEST_DNS_NAME env var for a containerboot instance.
	if err := enableIPForwarding(len(v4Backends) != 0, len(v6Backends) != 0, ""); err != nil {
		log.Printf("[unexpected] failed to ensure IP forwarding: %v", err)
	}

	updateFirewall := func(dst netip.Addr, backendTargets []netip.Addr) error {
		if err := nfr.DNATWithLoadBalancer(dst, backendTargets); err != nil {
			return fmt.Errorf("installing DNAT rules for ingress backends %+#v: %w", backendTargets, err)
		}
		// The backend might advertize MSS higher than that of the
		// tailscale interfaces. Clamp MSS of packets going out via
		// tailscale0 interface to its MTU to prevent broken connections
		// in environments where path MTU discovery is not working.
		if err := nfr.ClampMSSToPMTU("tailscale0", dst); err != nil {
			return fmt.Errorf("adding rule to clamp traffic via tailscale0: %v", err)
		}
		return nil
	}

	if len(v4Backends) != 0 {
		if !tsv4.IsValid() {
			log.Printf("backend targets %v contain at least one IPv4 address, but this node's Tailscale IPs do not contain a valid IPv4 address: %v", backendAddrs, tsIPs)
		} else if err := updateFirewall(tsv4, v4Backends); err != nil {
			return fmt.Errorf("Installing IPv4 firewall rules: %w", err)
		}
	}
	if len(v6Backends) != 0 && !tsv6.IsValid() {
		if !tsv6.IsValid() {
			log.Printf("backend targets %v contain at least one IPv6 address, but this node's Tailscale IPs do not contain a valid IPv6 address: %v", backendAddrs, tsIPs)
		} else if !nfr.HasIPV6NAT() {
			log.Printf("backend targets %v contain at least one IPv6 address, but the chosen firewall mode does not support IPv6 NAT", backendAddrs)
		} else if err := updateFirewall(tsv6, v6Backends); err != nil {
			return fmt.Errorf("Installing IPv6 firewall rules: %w", err)
		}
	}
	return nil
}
