// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"cmp"
	"fmt"
	"iter"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
	"tailscale.com/util/set"
)

// Note: the exported Node and Network are the configuration types;
// the unexported node and network are the runtime types that are actually
// used once the server is created.

// Config is the requested state of the natlab virtual network.
//
// The zero value is a valid empty configuration. Call AddNode
// and AddNetwork to methods on the returned Node and Network
// values to modify the config before calling NewServer.
// Once the NewServer is called, Config is no longer used.
type Config struct {
	nodes        []*Node
	networks     []*Network
	pcapFile     string
	blendReality bool
}

// SetPCAPFile sets the filename to write a pcap file to,
// or empty to disable pcap file writing.
func (c *Config) SetPCAPFile(file string) {
	c.pcapFile = file
}

// NumNodes returns the number of nodes in the configuration.
func (c *Config) NumNodes() int {
	return len(c.nodes)
}

// SetBlendReality sets whether to blend the real controlplane.tailscale.com and
// DERP servers into the virtual network. This is mostly useful for interactive
// testing when working on natlab.
func (c *Config) SetBlendReality(v bool) {
	c.blendReality = v
}

// FirstNetwork returns the first network in the config, or nil if none.
func (c *Config) FirstNetwork() *Network {
	if len(c.networks) == 0 {
		return nil
	}
	return c.networks[0]
}

func (c *Config) Nodes() iter.Seq2[int, *Node] {
	return slices.All(c.nodes)
}

func nodeMac(n int) MAC {
	// 52=TS then 0xcc for cccclient
	return MAC{0x52, 0xcc, 0xcc, 0xcc, 0xcc, byte(n)}
}

func routerMac(n int) MAC {
	// 52=TS then 0xee for 'etwork
	return MAC{0x52, 0xee, 0xee, 0xee, 0xee, byte(n)}
}

var lanSLAACBase = netip.MustParseAddr("fe80::50cc:ccff:fecc:cc01")

// nodeLANIP6 returns a node number's Link Local SLAAC IPv6 address,
// such as fe80::50cc:ccff:fecc:cc03 for node 3.
func nodeLANIP6(n int) netip.Addr {
	a := lanSLAACBase.As16()
	a[15] = byte(n)
	return netip.AddrFrom16(a)
}

// AddNode creates a new node in the world.
//
// The opts may be of the following types:
//   - *Network: zero, one, or more networks to add this node to
//   - TODO: more
//
// On an error or unknown opt type, AddNode returns a
// node with a carried error that gets returned later.
func (c *Config) AddNode(opts ...any) *Node {
	num := len(c.nodes) + 1
	n := &Node{
		num: num,
		mac: nodeMac(num),
	}
	c.nodes = append(c.nodes, n)
	for _, o := range opts {
		switch o := o.(type) {
		case *Network:
			if !slices.Contains(o.nodes, n) {
				o.nodes = append(o.nodes, n)
			}
			n.nets = append(n.nets, o)
		case TailscaledEnv:
			n.env = append(n.env, o)
		case NodeOption:
			switch o {
			case HostFirewall:
				n.hostFW = true
			case VerboseSyslog:
				n.verboseSyslog = true
			default:
				if n.err == nil {
					n.err = fmt.Errorf("unknown NodeOption %q", o)
				}
			}
		default:
			if n.err == nil {
				n.err = fmt.Errorf("unknown AddNode option type %T", o)
			}
		}
	}
	return n
}

// NodeOption is an option that can be passed to Config.AddNode.
type NodeOption string

const (
	HostFirewall  NodeOption = "HostFirewall"
	VerboseSyslog NodeOption = "VerboseSyslog"
)

// TailscaledEnv is а option that can be passed to Config.AddNode
// to set an environment variable for tailscaled.
type TailscaledEnv struct {
	Key, Value string
}

// AddNetwork add a new network.
//
// The opts may be of the following types:
//   - string IP address, for the network's WAN IP (if any)
//   - string netip.Prefix, for the network's LAN IP (defaults to 192.168.0.0/24)
//     if IPv4, or its WAN IPv6 + CIDR (e.g. "2000:52::1/64")
//   - NAT, the type of NAT to use
//   - NetworkService, a service to add to the network
//
// On an error or unknown opt type, AddNetwork returns a
// network with a carried error that gets returned later.
func (c *Config) AddNetwork(opts ...any) *Network {
	num := len(c.networks) + 1
	n := &Network{
		num: num,
		mac: routerMac(num),
	}
	c.networks = append(c.networks, n)
	for _, o := range opts {
		switch o := o.(type) {
		case string:
			if ip, err := netip.ParseAddr(o); err == nil {
				n.wanIP4 = ip
			} else if ip, err := netip.ParsePrefix(o); err == nil {
				// If the prefix is IPv4, treat it as the router's internal IPv4 address + CIDR.
				// If the prefix is IPv6, treat it as the router's WAN IPv6 + CIDR (typically a /64).
				if ip.Addr().Is4() {
					n.lanIP4 = ip
				} else if ip.Addr().Is6() {
					n.wanIP6 = ip
				}
			} else {
				if n.err == nil {
					n.err = fmt.Errorf("unknown string option %q", o)
				}
			}
		case NAT:
			n.natType = o
		case NetworkService:
			n.AddService(o)
		default:
			if n.err == nil {
				n.err = fmt.Errorf("unknown AddNetwork option type %T", o)
			}
		}
	}
	return n
}

// Node is the configuration of a node in the virtual network.
type Node struct {
	err error
	num int   // 1-based node number
	n   *node // nil until NewServer called

	env           []TailscaledEnv
	hostFW        bool
	verboseSyslog bool

	// TODO(bradfitz): this is halfway converted to supporting multiple NICs
	// but not done. We need a MAC-per-Network.

	mac  MAC
	nets []*Network
}

// Num returns the 1-based node number.
func (n *Node) Num() int {
	return n.num
}

// String returns the string "nodeN" where N is the 1-based node number.
func (n *Node) String() string {
	return fmt.Sprintf("node%d", n.num)
}

// MAC returns the MAC address of the node.
func (n *Node) MAC() MAC {
	return n.mac
}

func (n *Node) Env() []TailscaledEnv {
	return n.env
}

func (n *Node) HostFirewall() bool {
	return n.hostFW
}

func (n *Node) VerboseSyslog() bool {
	return n.verboseSyslog
}

func (n *Node) SetVerboseSyslog(v bool) {
	n.verboseSyslog = v
}

// IsV6Only reports whether this node is only connected to IPv6 networks.
func (n *Node) IsV6Only() bool {
	for _, net := range n.nets {
		if net.CanV4() {
			return false
		}
	}
	for _, net := range n.nets {
		if net.CanV6() {
			return true
		}
	}
	return false
}

// Network returns the first network this node is connected to,
// or nil if none.
func (n *Node) Network() *Network {
	if len(n.nets) == 0 {
		return nil
	}
	return n.nets[0]
}

// Network is the configuration of a network in the virtual network.
type Network struct {
	num     int // 1-based
	mac     MAC // MAC address of the router/gateway
	natType NAT

	wanIP6 netip.Prefix // global unicast router in host bits; CIDR is /64 delegated to LAN

	wanIP4    netip.Addr // IPv4 WAN IP, if any
	lanIP4    netip.Prefix
	nodes     []*Node
	breakWAN4 bool // whether to break WAN IPv4 connectivity

	svcs set.Set[NetworkService]

	latency  time.Duration // latency applied to interface writes
	lossRate float64       // chance of packet loss (0.0 to 1.0)

	// ...
	err error // carried error
}

// SetLatency sets the simulated network latency for this network.
func (n *Network) SetLatency(d time.Duration) {
	n.latency = d
}

// SetPacketLoss sets the packet loss rate for this network 0.0 (no loss) to 1.0 (total loss).
func (n *Network) SetPacketLoss(rate float64) {
	if rate < 0 {
		rate = 0
	} else if rate > 1 {
		rate = 1
	}
	n.lossRate = rate
}

// SetBlackholedIPv4 sets whether the network should blackhole all IPv4 traffic
// out to the Internet. (DHCP etc continues to work on the LAN.)
func (n *Network) SetBlackholedIPv4(v bool) {
	n.breakWAN4 = v
}

func (n *Network) CanV4() bool {
	return n.lanIP4.IsValid() || n.wanIP4.IsValid()
}

func (n *Network) CanV6() bool {
	return n.wanIP6.IsValid()
}

func (n *Network) CanTakeMoreNodes() bool {
	if n.natType == One2OneNAT {
		return len(n.nodes) == 0
	}
	return len(n.nodes) < 150
}

// NetworkService is a service that can be added to a network.
type NetworkService string

const (
	NATPMP NetworkService = "NAT-PMP"
	PCP    NetworkService = "PCP"
	UPnP   NetworkService = "UPnP"
)

// AddService adds a network service (such as port mapping protocols) to a
// network.
func (n *Network) AddService(s NetworkService) {
	if n.svcs == nil {
		n.svcs = set.Of(s)
	} else {
		n.svcs.Add(s)
	}
}

// initFromConfig initializes the server from the previous calls
// to NewNode and NewNetwork and returns an error if
// there were any configuration issues.
func (s *Server) initFromConfig(c *Config) error {
	netOfConf := map[*Network]*network{}
	if c.pcapFile != "" {
		pcf, err := os.OpenFile(c.pcapFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		nw, err := pcapgo.NewNgWriter(pcf, layers.LinkTypeEthernet)
		if err != nil {
			return err
		}
		pw := &pcapWriter{
			f: pcf,
			w: nw,
		}
		s.pcapWriter = pw
	}
	for i, conf := range c.networks {
		if conf.err != nil {
			return conf.err
		}
		if !conf.lanIP4.IsValid() && !conf.wanIP6.IsValid() {
			conf.lanIP4 = netip.MustParsePrefix("192.168.0.0/24")
		}
		n := &network{
			num:        conf.num,
			s:          s,
			mac:        conf.mac,
			portmap:    conf.svcs.Contains(NATPMP), // TODO: expand network.portmap
			wanIP6:     conf.wanIP6,
			v4:         conf.lanIP4.IsValid(),
			v6:         conf.wanIP6.IsValid(),
			wanIP4:     conf.wanIP4,
			lanIP4:     conf.lanIP4,
			breakWAN4:  conf.breakWAN4,
			latency:    conf.latency,
			lossRate:   conf.lossRate,
			nodesByIP4: map[netip.Addr]*node{},
			nodesByMAC: map[MAC]*node{},
			logf:       logger.WithPrefix(s.logf, fmt.Sprintf("[net-%v] ", conf.mac)),
		}
		netOfConf[conf] = n
		s.networks.Add(n)
		if conf.wanIP4.IsValid() {
			if conf.wanIP4.Is6() {
				return fmt.Errorf("invalid IPv6 address in wanIP")
			}
			if _, ok := s.networkByWAN.Lookup(conf.wanIP4); ok {
				return fmt.Errorf("two networks have the same WAN IP %v; Anycast not (yet?) supported", conf.wanIP4)
			}
			s.networkByWAN.Insert(netip.PrefixFrom(conf.wanIP4, 32), n)
		}
		if conf.wanIP6.IsValid() {
			if conf.wanIP6.Addr().Is4() {
				return fmt.Errorf("invalid IPv4 address in wanIP6")
			}
			if _, ok := s.networkByWAN.LookupPrefix(conf.wanIP6); ok {
				return fmt.Errorf("two networks have the same WAN IPv6 %v; Anycast not (yet?) supported", conf.wanIP6)
			}
			s.networkByWAN.Insert(conf.wanIP6, n)
		}
		n.lanInterfaceID = must.Get(s.pcapWriter.AddInterface(pcapgo.NgInterface{
			Name:     fmt.Sprintf("network%d-lan", i+1),
			LinkType: layers.LinkTypeIPv4,
		}))
		n.wanInterfaceID = must.Get(s.pcapWriter.AddInterface(pcapgo.NgInterface{
			Name:     fmt.Sprintf("network%d-wan", i+1),
			LinkType: layers.LinkTypeIPv4,
		}))
	}
	for _, conf := range c.nodes {
		if conf.err != nil {
			return conf.err
		}
		n := &node{
			num:           conf.num,
			mac:           conf.mac,
			net:           netOfConf[conf.Network()],
			verboseSyslog: conf.VerboseSyslog(),
		}
		n.interfaceID = must.Get(s.pcapWriter.AddInterface(pcapgo.NgInterface{
			Name:     n.String(),
			LinkType: layers.LinkTypeEthernet,
		}))
		conf.n = n
		if _, ok := s.nodeByMAC[n.mac]; ok {
			return fmt.Errorf("two nodes have the same MAC %v", n.mac)
		}
		s.nodes = append(s.nodes, n)
		s.nodeByMAC[n.mac] = n

		if n.net.v4 {
			// Allocate a lanIP for the node. Use the network's CIDR and use final
			// octet 101 (for first node), 102, etc. The node number comes from the
			// last octent of the MAC address (0-based)
			ip4 := n.net.lanIP4.Addr().As4()
			ip4[3] = 100 + n.mac[5]
			n.lanIP = netip.AddrFrom4(ip4)
			n.net.nodesByIP4[n.lanIP] = n
		}
		n.net.nodesByMAC[n.mac] = n
	}

	// Now that nodes are populated, set up NAT:
	for _, conf := range c.networks {
		n := netOfConf[conf]
		natType := cmp.Or(conf.natType, EasyNAT)
		if err := n.InitNAT(natType); err != nil {
			return err
		}
	}

	return nil
}
