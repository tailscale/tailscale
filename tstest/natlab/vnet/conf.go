// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vnet

import (
	"cmp"
	"fmt"
	"log"
	"net/netip"
	"os"
	"slices"

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
	nodes    []*Node
	networks []*Network
	pcapFile string
}

func (c *Config) SetPCAPFile(file string) {
	c.pcapFile = file
}

func (c *Config) NumNodes() int {
	return len(c.nodes)
}

func (c *Config) FirstNetwork() *Network {
	if len(c.networks) == 0 {
		return nil
	}
	return c.networks[0]
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
	num := len(c.nodes)
	n := &Node{
		num: num + 1,
		mac: MAC{0x52, 0xcc, 0xcc, 0xcc, 0xcc, byte(num) + 1}, // 52=TS then 0xcc for ccclient
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
//   - NAT, the type of NAT to use
//   - NetworkService, a service to add to the network
//
// On an error or unknown opt type, AddNetwork returns a
// network with a carried error that gets returned later.
func (c *Config) AddNetwork(opts ...any) *Network {
	num := len(c.networks)
	n := &Network{
		mac: MAC{0x52, 0xee, 0xee, 0xee, 0xee, byte(num) + 1}, // 52=TS then 0xee for 'etwork
	}
	c.networks = append(c.networks, n)
	for _, o := range opts {
		switch o := o.(type) {
		case string:
			if ip, err := netip.ParseAddr(o); err == nil {
				n.wanIP = ip
			} else if ip, err := netip.ParsePrefix(o); err == nil {
				n.lanIP = ip
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
	mac     MAC // MAC address of the router/gateway
	natType NAT

	wanIP netip.Addr
	lanIP netip.Prefix
	nodes []*Node

	svcs set.Set[NetworkService]

	// ...
	err error // carried error
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
		if !conf.lanIP.IsValid() {
			conf.lanIP = netip.MustParsePrefix("192.168.0.0/24")
		}
		n := &network{
			s:         s,
			mac:       conf.mac,
			portmap:   conf.svcs.Contains(NATPMP), // TODO: expand network.portmap
			wanIP:     conf.wanIP,
			lanIP:     conf.lanIP,
			nodesByIP: map[netip.Addr]*node{},
			logf:      logger.WithPrefix(log.Printf, fmt.Sprintf("[net-%v] ", conf.mac)),
		}
		netOfConf[conf] = n
		s.networks.Add(n)
		if _, ok := s.networkByWAN[conf.wanIP]; ok {
			return fmt.Errorf("two networks have the same WAN IP %v; Anycast not (yet?) supported", conf.wanIP)
		}
		s.networkByWAN[conf.wanIP] = n
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

		// Allocate a lanIP for the node. Use the network's CIDR and use final
		// octet 101 (for first node), 102, etc. The node number comes from the
		// last octent of the MAC address (0-based)
		ip4 := n.net.lanIP.Addr().As4()
		ip4[3] = 100 + n.mac[5]
		n.lanIP = netip.AddrFrom4(ip4)
		n.net.nodesByIP[n.lanIP] = n
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
