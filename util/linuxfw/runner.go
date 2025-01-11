package linuxfw

import (
	"net/netip"

	"tailscale.com/types/logger"
)

// // PortMap is the port mapping for a service rule.
type PortMap struct {
	// MatchPort is the local port to which the rule should apply.
	MatchPort uint16
	// TargetPort is the port to which the traffic should be forwarded.
	TargetPort uint16
	// Protocol is the protocol to match packets on. Only TCP and UDP are
	// supported.
	Protocol string
}

// NetfilterRunner abstracts helpers to run netfilter commands. It is
// implemented by linuxfw.IPTablesRunner and linuxfw.NfTablesRunner.
type NetfilterRunner interface {
	// AddLoopbackRule adds a rule to permit loopback traffic to addr. This rule
	// is added only if it does not already exist.
	AddLoopbackRule(addr netip.Addr) error

	// DelLoopbackRule removes the rule added by AddLoopbackRule.
	DelLoopbackRule(addr netip.Addr) error

	// AddHooks adds rules to conventional chains like "FORWARD", "INPUT" and
	// "POSTROUTING" to jump from those chains to tailscale chains.
	AddHooks() error

	// DelHooks deletes rules added by AddHooks.
	DelHooks(logf logger.Logf) error

	// AddChains creates custom Tailscale chains.
	AddChains() error

	// DelChains removes chains added by AddChains.
	DelChains() error

	// AddBase adds rules reused by different other rules.
	AddBase(tunname string) error

	// DelBase removes rules added by AddBase.
	DelBase() error

	// AddSNATRule adds the netfilter rule to SNAT incoming traffic over
	// the Tailscale interface destined for local subnets. An error is
	// returned if the rule already exists.
	AddSNATRule() error

	// DelSNATRule removes the rule added by AddSNATRule.
	DelSNATRule() error

	// AddStatefulRule adds a netfilter rule for stateful packet filtering
	// using conntrack.
	AddStatefulRule(tunname string) error

	// DelStatefulRule removes a netfilter rule for stateful packet filtering
	// using conntrack.
	DelStatefulRule(tunname string) error

	// HasIPV6 reports true if the system supports IPv6.
	HasIPV6() bool

	// HasIPV6NAT reports true if the system supports IPv6 NAT.
	HasIPV6NAT() bool

	// HasIPV6Filter reports true if the system supports IPv6 filter tables
	// This is only meaningful for iptables implementation, where hosts have
	// partial ipables support (i.e missing filter table). For nftables
	// implementation, this will default to the value of HasIPv6().
	HasIPV6Filter() bool

	// AddDNATRule adds a rule to the nat/PREROUTING chain to DNAT traffic
	// destined for the given original destination to the given new destination.
	// This is used to forward all traffic destined for the Tailscale interface
	// to the provided destination, as used in the Kubernetes ingress proxies.
	AddDNATRule(origDst, dst netip.Addr) error

	// DNATWithLoadBalancer adds a rule to the nat/PREROUTING chain to DNAT
	// traffic destined for the given original destination to the given new
	// destination(s) using round robin to load balance if more than one
	// destination is provided. This is used to forward all traffic destined
	// for the Tailscale interface to the provided destination(s), as used
	// in the Kubernetes ingress proxies.
	DNATWithLoadBalancer(origDst netip.Addr, dsts []netip.Addr) error

	// EnsureSNATForDst sets up firewall to mask the source for traffic destined for dst to src:
	// - creates a SNAT rule if it doesn't already exist
	// - deletes any pre-existing rules matching the destination
	// This is used to forward traffic destined for the local machine over
	// the Tailscale interface, as used in the Kubernetes egress proxies.
	EnsureSNATForDst(src, dst netip.Addr) error

	// DNATNonTailscaleTraffic adds a rule to the nat/PREROUTING chain to DNAT
	// all traffic inbound from any interface except exemptInterface to dst.
	// This is used to forward traffic destined for the local machine over
	// the Tailscale interface, as used in the Kubernetes egress proxies.
	DNATNonTailscaleTraffic(exemptInterface string, dst netip.Addr) error

	EnsurePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error

	DeletePortMapRuleForSvc(svc, tun string, targetIP netip.Addr, pm PortMap) error

	DeleteSvc(svc, tun string, targetIPs []netip.Addr, pm []PortMap) error

	// ClampMSSToPMTU adds a rule to the mangle/FORWARD chain to clamp MSS for
	// traffic destined for the provided tun interface.
	ClampMSSToPMTU(tun string, addr netip.Addr) error

	// AddMagicsockPortRule adds a rule to the ts-input chain to accept
	// incoming traffic on the specified port, to allow magicsock to
	// communicate.
	AddMagicsockPortRule(port uint16, network string) error

	// DelMagicsockPortRule removes the rule created by AddMagicsockPortRule,
	// if it exists.
	DelMagicsockPortRule(port uint16, network string) error
}
