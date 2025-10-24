// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Upstream DNS forwarding over a TUN interface, using gVisor UDP transport
// A TUN interface allows us inject DNS packets into the host as though they
// arrived from a remote device.  Specifically this allows us to set the source
// IP address of the DNS packets to reflect the address of their origin node in
// the tailnet.  This 'unmasks' the true origin of a request, such that policies
// can be implemented and access records maintained.
// The source address must occupy a subnet which is distinct from the tailnet if
// they both share a common network namespace.  To facilitate this, a 'NETMAP'
// function is provided which will 1:1 map a tailnet source IP address in the
// CGNAT subnet (100.64.0.0/10) to another subnet such as 10.64.0.0/10.  The
// source-NAT NETMAP functionality is identical to that provided by linux
// iptables SNAT.  Note the size of the DNS subnet could be smaller than the entire
// CGNAT subnet if your tailnet devices occupy only a subset of the CGNAT.

// ./wgengine/netstack/netstack.go
// https://viveksb007.github.io/2024/10/gvisor-userspace-tcp-server-client/

//go:build linux
// +build linux

package resolver

import (
	"bytes"
	"context"
	"fmt"
	// "log"
	"os"
	"sync"
	"net" // UDPConn interface
	"net/netip"
	"encoding/binary"

	// "gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/waiter"

	"tailscale.com/types/logger"
	// "tailscale.com/types/nettype"

	// Netlink library
	"github.com/tailscale/netlink"
)

const nicID = 1

// ConnPacketConn is the interface that's a superset of net.Conn and net.PacketConn.
type ConnPacketConn interface {
	net.Conn
	net.PacketConn
}

// Return an Addr with the 'ip' prefix portion replaced by 'net' prefix.
// This feels like a function that should be part of the netip module...
func netipNetMap(ip netip.Addr, net netip.Prefix) (ret netip.Addr, err error) {
	if !net.IsValid() {
		return netip.Addr{}, fmt.Errorf("netipNetMap: supplied network is invalid")
	}
	if !ip.IsValid() {
		return netip.Addr{}, fmt.Errorf("netipNetMap: supplied IP is invalid")
	}
	if net.Addr().Is4() != ip.Is4() {
		return netip.Addr{}, fmt.Errorf("netipNetMap: supplied IP/network conflicting IPv4 / IPv6")
	}
	// Now the 'heavy lifting' is performed to extract the binary representations
	if ip.Is4() {
		ip4 := ip.AsSlice()
		ip4b := binary.BigEndian.Uint32(ip4)
		net4 := net.Addr().AsSlice()
		net4b := binary.BigEndian.Uint32(net4)
		bits := net.Bits()
		// clear prefix bits from IP
		ip4b = (ip4b << bits) >> bits
		// keep prefix bits from network
		net4b = (net4b >> (32 - bits)) << (32 - bits)
		// Now we 'OR' the bit-fields together to form the resultant IP
		ret4b := net4b | ip4b
		// Binary->Slice
		ret4 := [4]byte{}
		binary.BigEndian.PutUint32(ret4[:], ret4b)
		return netip.AddrFrom4(ret4), nil
	} else {
		// A 128-bit IPv6 address is split into two 64-bit segments
		// as we don't have a native 128-bit type
		ip6 := ip.AsSlice()
		ip6bu := binary.BigEndian.Uint64(ip6[:8])
		ip6bl := binary.BigEndian.Uint64(ip6[8:])
		net6 := net.Addr().AsSlice()
		net6bu := binary.BigEndian.Uint64(net6[:8])
		net6bl := binary.BigEndian.Uint64(net6[8:])
		bits := net.Bits()
		if bits < 64 {
			// IP part: 0..63 prefix bits are cleared (don't modify lower 64-bits of IP)
			ip6bu = (ip6bu << bits) >> bits
			// network part: 0..63 prefix bits are kept
			net6bl = 0
			net6bu = (net6bu >> (64 - bits)) << (64 - bits)
		} else {
			// 64..128 prefix bits are cleared
			ip6bu = 0
			ip6bl = (ip6bl << (bits - 64)) >> (bits - 64)
			// 64..128 prefix bits are kept (don't modify upper 64-bits of network)
			net6bl = (net6bl >> (128 - bits)) << (128 - bits)
		}
		// Now we 'OR' the bit-fields together to form the resultant IP
		ret6bu := net6bu | ip6bu
		ret6bl := net6bl | ip6bl
		// Binary->Slice
		ret6 := [16]byte{}
		binary.BigEndian.PutUint64(ret6[:8], ret6bu)
		binary.BigEndian.PutUint64(ret6[8:], ret6bl)
		return netip.AddrFrom16(ret6), nil
	}
}

// writer reads from standard input and writes to the endpoint until standard
// input is closed. It signals that it's done by closing the provided channel.
func writer(ch chan struct{}, ep tcpip.Endpoint) {
	defer func() {
		ep.Shutdown(tcpip.ShutdownWrite)
		close(ch)
	}()

	var b bytes.Buffer
	if err := func() error {
		for {
			if _, err := b.ReadFrom(os.Stdin); err != nil {
				return fmt.Errorf("b.ReadFrom failed: %w", err)
			}

			for b.Len() != 0 {
				if _, err := ep.Write(&b, tcpip.WriteOptions{Atomic: true}); err != nil {
					return fmt.Errorf("ep.Write failed: %s", err)
				}
			}
		}
	}(); err != nil {
		fmt.Println(err)
	}
}

type forwarder_tun struct {
	logf	    logger.Logf
	ipstack     *stack.Stack
	ifName      string
	// Source-NAT prefix to apply to the outbound source address
	snatPrefixIPv4 netip.Prefix
	snatPrefixIPv6 netip.Prefix
	// tun interface address of this node IPv4 / IPv6
	selfAddrIPv4  netip.Prefix
	selfAddrIPv6  netip.Prefix

	mu sync.Mutex
	// connsOpenBySubnetIP keeps track of number of connections open
	// for each subnet IP temporarily registered on netstack for active
	// TCP connections, so they can be unregistered when connections are
	// closed.
	connsOpenBySubnetIP map[netip.Addr]int
}

func newForwarderTun(logf logger.Logf, ifName string) (*forwarder_tun, error) {

	// Create the stack with ipv4 and tcp protocols, then add a tun-based
	// NIC and ipv4 address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})

	fd, err := tun.Open(ifName)
	if err != nil {
		return nil, fmt.Errorf("tcpip.tun.Open(%s):Error=%v", ifName, err)
	}

	// logf("Configure interface \"%s\" via netlink", ifName)
	// link, errGetLink := netlink.LinkByName(ifName)
	// if errGetLink != nil {
	// 	return nil, fmt.Errorf("netlink.LinkByName failed: %v", errGetLink)
	// }

	// // Hard-code the interface MTU for now
	var mtu uint32 = 1500
	// errSetMTU := netlink.LinkSetMTU(link, mtu)
	// if errSetMTU != nil {
	// 	return nil, fmt.Errorf("netlink.LinkSetMTU failed: %v", errSetMTU)
	// }


	// TODO
	// mtu, err := rawfile.GetMTU(ifName)
	// if err != nil {
	// 	return nil, fmt.Errorf("tcpip.rawfile.GetMTU(%s):Error=%v", ifName, err)
	// }

	linkEP, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: mtu})
	// linkEP, err := fdbased.New(&fdbased.Options{FDs: []int{fd}})
	if err != nil {
		return nil, fmt.Errorf("tcpip.fdbased.New:Error=%v", err)
	}

	// opts := stack.NICOptions{Name: ifName}
	// stackErr := s.CreateNICWithOptions(nicID, sniffer.New(linkEP), opts)
	stackErr := s.CreateNIC(nicID, sniffer.New(linkEP))
	// stackErr := s.CreateNIC(nicID, linkEP)
	if stackErr != nil {
		return nil, fmt.Errorf("tcpip.CreateNIC:Error=%v", stackErr.String())
	}

	// We can route all packets within netstack to the single interface
	// This does not affect the host OS routes
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	ft := &forwarder_tun{
		logf:                logger.WithPrefix(logf, "forwarder_tun: "),
		ipstack:             s,
		ifName:              ifName,
		connsOpenBySubnetIP: make(map[netip.Addr]int),
	}
	return ft, nil
}

func (ft *forwarder_tun) setSnatPrefix(snatPrefixIPv4 netip.Prefix, selfAddrs []netip.Prefix) error {
	// Create an empty IPv6 prefix for now...
	var snatPrefixIPv6 netip.Prefix

	// Record prefix
	ft.snatPrefixIPv4 = snatPrefixIPv4

	// Get the IPv4 address of this node
	var selfAddrIPv4, selfAddrIPv6 netip.Prefix
	for _, selfAddr := range selfAddrs {
		if selfAddr.Addr().Is4() {
			selfAddrIPv4 = selfAddr
		} else if selfAddr.Addr().Is6() {
			selfAddrIPv6 = selfAddr
		}
	}

	addrAddIPv4 :=    selfAddrIPv4.IsValid() && (!ft.selfAddrIPv4.IsValid() || (ft.selfAddrIPv4 != selfAddrIPv4)) && snatPrefixIPv4.IsValid()
	addrDelIPv4 := ft.selfAddrIPv4.IsValid() && (   !selfAddrIPv4.IsValid() || (ft.selfAddrIPv4 != selfAddrIPv4)) && snatPrefixIPv4.IsValid()
	addrAddIPv6 :=    selfAddrIPv6.IsValid() && (!ft.selfAddrIPv6.IsValid() || (ft.selfAddrIPv6 != selfAddrIPv6)) && snatPrefixIPv6.IsValid()
	addrDelIPv6 := ft.selfAddrIPv6.IsValid() && (!ft.selfAddrIPv6.IsValid() || (ft.selfAddrIPv6 != selfAddrIPv6)) && snatPrefixIPv6.IsValid()
	linkUpdate := addrAddIPv4 || addrDelIPv4 || addrAddIPv6 || addrDelIPv6

	if linkUpdate {
		ft.logf("Applying DNS interface \"%s\" updates:", ft.ifName)
		link, err := netlink.LinkByName(ft.ifName)
		if err != nil {
			return fmt.Errorf("netlink.LinkByName failed: %v", err)
		}

		// Bring down the link before changing settings
		// This will also remove all existing routes to this network
		netlink.LinkSetDown(link)

		// The DNS TUN interface addresses reflect the SNAT map
		if addrDelIPv4 {
			tunAddr, _ := netipNetMap(ft.selfAddrIPv4.Addr(), snatPrefixIPv4)
			tunSubnet  := netip.PrefixFrom(tunAddr, ft.selfAddrIPv4.Bits())

			ft.logf("Delete IPv4 address %v", tunSubnet)
			nlAddr, _ := netlink.ParseAddr(tunSubnet.String())
			netlink.AddrDel(link, nlAddr)
		}
		if addrAddIPv4 {
			tunAddr, _ := netipNetMap(selfAddrIPv4.Addr(), snatPrefixIPv4)
			tunSubnet  := netip.PrefixFrom(tunAddr, selfAddrIPv4.Bits())

			ft.logf("Add IPv4 address %v", tunSubnet)
			nlAddr, _ := netlink.ParseAddr(tunSubnet.String())
			netlink.AddrAdd(link, nlAddr)
		}
		if addrDelIPv6 {
			tunAddr, _ := netipNetMap(ft.selfAddrIPv6.Addr(), snatPrefixIPv6)
			tunSubnet  := netip.PrefixFrom(tunAddr, ft.selfAddrIPv6.Bits())

			ft.logf("Delete IPv6 address %v", tunSubnet)
			nlAddr, _ := netlink.ParseAddr(tunSubnet.String())
			netlink.AddrDel(link, nlAddr)
		}
		if addrAddIPv6 {
			tunAddr, _ := netipNetMap(selfAddrIPv6.Addr(), snatPrefixIPv6)
			tunSubnet  := netip.PrefixFrom(tunAddr, selfAddrIPv6.Bits())

			ft.logf("Add IPv6 address %v", tunSubnet)
			nlAddr, _ := netlink.ParseAddr(tunSubnet.String())
			netlink.AddrAdd(link, nlAddr)
		}

		// Bring back up the link after changing settings
		netlink.LinkSetUp(link)

		// Network is UP, now we can add routes...
		if addrAddIPv4 {
			tunAddr, _ := netipNetMap(selfAddrIPv4.Addr(), snatPrefixIPv4)
			ft.logf("Add IPv4 route (%v via %v dev %s)", snatPrefixIPv4, tunAddr, ft.ifName)
			_, dst, err := net.ParseCIDR(snatPrefixIPv4.String())
			if err != nil {
				return fmt.Errorf("Failed to parse destination CIDR: %v", err)
			}
			gateway := net.ParseIP(tunAddr.String())
			if gateway == nil {
				return fmt.Errorf("Failed to parse gateway IP(%v)", tunAddr)
			}
			route := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Gw: gateway}
			if err := netlink.RouteAdd(route); err != nil {
				return fmt.Errorf("Failed to add route: %v", err)
			}
		}
	}

	// Update to refect the new interface settings
	ft.selfAddrIPv4 = selfAddrIPv4
	ft.selfAddrIPv6 = selfAddrIPv6

	// Add route.
	// Generate a new tcpip.Subnet from netip.Prefix
	// Is there a better way?
	// subnetAddr := snatPrefixIPv4.Addr()
	// var addrAllOnes netip.Addr
	// if subnetAddrIPv4.Is6() {
	// 	addrAllOnes = netip.AddrFrom16([16]byte{
	// 	    0xff, 0xff, 0xff, 0xff,
	// 	    0xff, 0xff, 0xff, 0xff,
	// 	    0xff, 0xff, 0xff, 0xff,
	// 	    0xff, 0xff, 0xff, 0xff,
	// 	})
	// } else {
	// 	// Generate a new tcpip.Subnet from netip.Prefix
	// 	// Is there a better way?
	// 	addrAllOnes = netip.AddrFrom4([4]byte{
	// 	    0xff, 0xff, 0xff, 0xff,
	// 	})
	// }
	// prefixAllOnes, err := addrAllOnes.Prefix(subnetBits)
	// if err != nil {
	// 	return err
	// }
	// subnetMask := prefixAllOnes.Addr()

	// subnet, err := tcpip.NewSubnet(
	// 	tcpip.AddrFromSlice(subnetAddr.AsSlice()),
	// 	tcpip.MaskFromBytes(subnetMask.AsSlice()),
	// )
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (ft *forwarder_tun) addSubnetAddress(ip netip.Addr) {
	ft.mu.Lock()
	ft.connsOpenBySubnetIP[ip]++
	needAdd := ft.connsOpenBySubnetIP[ip] == 1
	ft.mu.Unlock()
	// Only register address into netstack for first concurrent connection.
	if needAdd {
		pa := tcpip.ProtocolAddress{
		        AddressWithPrefix: tcpip.AddrFromSlice(ip.AsSlice()).WithPrefix(),
		}
		if ip.Is4() {
			 pa.Protocol = ipv4.ProtocolNumber
		} else if ip.Is6() {
			pa.Protocol = ipv6.ProtocolNumber
		}
		ft.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
	}
}

type udpEndpoint struct {
	wq *waiter.Queue
	ep tcpip.Endpoint
}

func udpConnect(s *stack.Stack, nicId tcpip.NICID, srcAddrPort, dstAddrPort netip.AddrPort) (*udpEndpoint, error) {

	srcAddr := srcAddrPort.Addr()
	srcPort := srcAddrPort.Port()

	var networkProto tcpip.NetworkProtocolNumber
	if srcAddr.Is4() {
		networkProto = ipv4.ProtocolNumber
	} else if srcAddr.Is6() {
		networkProto = ipv6.ProtocolNumber
	}

	dstAddress := tcpip.FullAddress{
		NIC:  nicId,
		Addr: tcpip.AddrFromSlice(dstAddrPort.Addr().AsSlice()),
		Port: dstAddrPort.Port(),
	}

	wq := &waiter.Queue{}
	ep, err := s.NewEndpoint(udp.ProtocolNumber, networkProto, wq)
	if err != nil {
		return nil, fmt.Errorf("NewEndPoint failed: %v", err)
	}

	// Explicit bind if a source port is specified.
	if srcPort != 0 {
		srcAddress := tcpip.FullAddress{
			NIC:  nicId,
			Addr: tcpip.AddrFromSlice(srcAddr.AsSlice()),
			Port: srcPort,
		}
		if err := ep.Bind(srcAddress); err != nil {
			ep.Close()
			return nil, fmt.Errorf("forwarder_tun: Bind failed: (%v): %v", srcAddress, err)
		}
	}

	entry, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&entry)

	err = ep.Connect(dstAddress)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		<-ch
		err = ep.LastError()
	}
	if err != nil {
		return nil, fmt.Errorf("Unable to connect: (%v): %v", dstAddress, err)
	}

	return &udpEndpoint{wq, ep}, nil
}

func (ft *forwarder_tun) DialUDP(srcAddrPort, dstAddrPort netip.AddrPort) (*gonet.UDPConn, error) {

	// Apply SNAT to source address if the SNAT prefix is valid
	if !ft.snatPrefixIPv4.IsValid() {
		return nil, fmt.Errorf("Must configure a vaild DNS SNAT prefix")
	}
	// To support the option --dns-upstream-snat-netmap we will form a DNS query source address
	// from the address of the tailnet node making the query
	// This will effectively unmask the source-IP of the DNS query, allowing meaningful DNS
	// rules and logging to be applied based on the source address of the tailnet device
	// We can not map the source IP to the same subnet as the tailnet node becuase we
	// the wireguard TUN interface can not be trivially 'shared'
	// NOTE: It should be possible to apply a NETMAP rule via iptables SNAT rules to counter-map
	// the source subnet employed here back into the subnet occupies by the the tailnet!
	// If a counter-map is employed it is assumed that any conflicting source port numbers
	// would be detected and corrected in the normal way by the linux firewall
	srcAddrSNAT, netipNetMapErr := netipNetMap(srcAddrPort.Addr(), ft.snatPrefixIPv4)
	if netipNetMapErr != nil {
		return nil, netipNetMapErr
	}
	// TODO: We don't need this?  We already have a default route to the raw TUN interface in our userspace stack
	ft.addSubnetAddress(srcAddrSNAT)

	// We use the gVisor gonet adapter to obtain a gonet::UDPConn via a call to DialUDP
	// https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/adapters/gonet#UDPConn
	// -> "A UDPConn is a wrapper around a UDP tcpip.Endpoint that implements net.Conn and net.PacketConn."
	// -> func DialUDP(s *stack.Stack, laddr, raddr *tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*UDPConn, error)
	var networkProto tcpip.NetworkProtocolNumber
	if srcAddrPort.Addr().Is4() {
		networkProto = ipv4.ProtocolNumber
	} else if srcAddrPort.Addr().Is6() {
		networkProto = ipv6.ProtocolNumber
	}

	srcAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(srcAddrSNAT.AsSlice()),
		// We re-use the source port (from the upstream node), but we could also let netstack
		// auto-generate it's own source port by removing this.
		Port: srcAddrPort.Port(),
	}
	dstAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(dstAddrPort.Addr().AsSlice()),
		Port: dstAddrPort.Port(),
	}
	// ft.logf("DialUDP: src(%v:%d)->dst(%v)", srcAddrSNAT, srcAddrPort, dstAddrPort)
	conn, connErr := gonet.DialUDP(ft.ipstack, srcAddress, dstAddress, networkProto)
	if connErr != nil {
		return nil, connErr
	}
	return conn, nil
}

func (ft *forwarder_tun) DialTCP(ctx context.Context, srcAddrPort, dstAddrPort netip.AddrPort) (*gonet.TCPConn, error) {

	// Apply SNAT to source address if the SNAT prefix is valid
	if !ft.snatPrefixIPv4.IsValid() {
		return nil, fmt.Errorf("Must configure a vaild DNS SNAT prefix")
	}
	// To support the option --dns-upstream-snat-netmap we will form a DNS query source address
	// from the address of the tailnet node making the query
	// This will effectively unmask the source-IP of the DNS query, allowing meaningful DNS
	// rules and logging to be applied based on the source address of the tailnet device
	// We can not map the source IP to the same subnet as the tailnet node becuase we
	// the wireguard TUN interface can not be trivially 'shared'
	// NOTE: It should be possible to apply a NETMAP rule via iptables SNAT rules to counter-map
	// the source subnet employed here back into the subnet occupies by the the tailnet!
	// If a counter-map is employed it is assumed that any conflicting source port numbers
	// would be detected and corrected in the normal way by the linux firewall
	srcAddrSNAT, netipNetMapErr := netipNetMap(srcAddrPort.Addr(), ft.snatPrefixIPv4)
	if netipNetMapErr != nil {
		return nil, netipNetMapErr
	}
	// TODO: We don't need this?  We already have a default route to the raw TUN interface in our userspace stack
	ft.addSubnetAddress(srcAddrSNAT)

	// We use the gVisor gonet adapter to obtain a gonet::UDPConn via a call to DialUDP
	// https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/adapters/gonet#UDPConn
	// -> "A UDPConn is a wrapper around a UDP tcpip.Endpoint that implements net.Conn and net.PacketConn."
	// -> func DialUDP(s *stack.Stack, laddr, raddr *tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*UDPConn, error)
	var networkProto tcpip.NetworkProtocolNumber
	if srcAddrPort.Addr().Is4() {
		networkProto = ipv4.ProtocolNumber
	} else if srcAddrPort.Addr().Is6() {
		networkProto = ipv6.ProtocolNumber
	}

	srcAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(srcAddrSNAT.AsSlice()),
		// We re-use the source port (from the upstream node), but we could also let netstack
		// auto-generate it's own source port by removing this.
		Port: srcAddrPort.Port(),
	}
	dstAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(dstAddrPort.Addr().AsSlice()),
		Port: dstAddrPort.Port(),
	}
	// ft.logf("DialUDP: src(%v:%d)->dst(%v)", srcAddrSNAT, srcAddrPort, dstAddrPort)
	conn, connErr := gonet.DialTCPWithBind(ctx, ft.ipstack, srcAddress, dstAddress, networkProto)
	if connErr != nil {
		return nil, connErr
	}
	return conn, nil
}

func (ft *forwarder_tun) sendUDP(srcAddrPort, dstAddrPort netip.AddrPort, payload []byte) (ret []byte, err error) {

	if !dstAddrPort.IsValid() {
		return nil, fmt.Errorf("destination address invalid")
	}

	srcAddr := srcAddrPort.Addr()
	srcPort := srcAddrPort.Port()

	// Apply SNAT to source address if the SNAT prefix is valid
	if ft.snatPrefixIPv4.IsValid() {
		// To support the option --dns-upstream-snat-netmap we will form a DNS query source address
		// from the address of the tailnet node making the query
		// This will effectively unmask the source-IP of the DNS query, allowing meaningful DNS
		// rules and logging to be applied based on the source address of the tailnet device
		// We can not map the source IP to the same subnet as the tailnet node becuase we
		// the wireguard TUN interface can not be trivially 'shared'
		// NOTE: It should be possible to apply a NETMAP rule via iptables SNAT rules to counter-map
		// the source subnet employed here back into the subnet occupies by the the tailnet!
		// If a counter-map is employed it is assumed that any conflicting source port numbers
		// would be detected and corrected in the normal way by the linux firewall
		var err error
		srcAddr, err = netipNetMap(srcAddrPort.Addr(), ft.snatPrefixIPv4)
		if err != nil {
			return nil, err
		}
	}

	ft.addSubnetAddress(srcAddr)

	srcAddrPortNat := netip.AddrPortFrom(srcAddr, srcPort)

	ft.logf("sendUDPviaTun: src(%v)->dst(%v)", srcAddrPortNat, dstAddrPort)

	endpointQueue, err := udpConnect(ft.ipstack, nicID, srcAddrPortNat, dstAddrPort)
	if err != nil {
		return nil, err
	}

	// ft.logf("Connected: src(%v)->dst(%v)", endpointQueue.ep.GetLocalAddress(), endpointQueue.ep.GetRemoteAddress())

	// tcpip.UDPConn
	conn := gonet.NewUDPConn(endpointQueue.wq, endpointQueue.ep)
	defer conn.Close()

	_, err1 := conn.Write(payload)
	if err1 != nil {
		return nil, fmt.Errorf("Failed to write to connection: %v", err)
	}

	buf := make([]byte, 2048)
	n, err1 := conn.Read(buf)
	if err1 != nil {
		return nil, fmt.Errorf("Failed to read from connection: %v", err)
	}
	return buf[:n], nil

	// // Start the writer in its own goroutine.
	// writerCompletedCh := make(chan struct{})
	// go writer(writerCompletedCh, ep) // S/R-SAFE: sample code.

	// // Read data and write to standard output until the peer closes the
	// // connection from its side.
	// waitEntry, notifyCh = waiter.NewChannelEntry(waiter.ReadableEvents)
	// wq.EventRegister(&waitEntry)
	// for {
	// 	_, err := ep.Read(os.Stdout, tcpip.ReadOptions{})
	// 	if err != nil {
	// 		if _, ok := err.(*tcpip.ErrClosedForReceive); ok {
	// 			break
	// 		}

	// 		if _, ok := err.(*tcpip.ErrWouldBlock); ok {
	// 			<-notifyCh
	// 			continue
	// 		}

	// 		log.Fatal("Read() failed:", err)
	// 	}
	// }
	// wq.EventUnregister(&waitEntry)

	// // The reader has completed. Now wait for the writer as well.
	// <-writerCompletedCh

	// ep.Close()
}

