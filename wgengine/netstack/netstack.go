// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package netstack wires up gVisor's netstack into Tailscale.
package netstack

import (
	"bytes"
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/conn"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"tailscale.com/envknob"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/metrics"
	"tailscale.com/net/dns"
	"tailscale.com/net/ipset"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/netx"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsaddr"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/proxymap"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/set"
	"tailscale.com/version"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netstack/gro"
)

const debugPackets = false

// If non-zero, these override the values returned from the corresponding
// functions, below.
var (
	maxInFlightConnectionAttemptsForTest          int
	maxInFlightConnectionAttemptsPerClientForTest int
)

// maxInFlightConnectionAttempts returns the global number of in-flight
// connection attempts that we allow for a single netstack Impl. Any new
// forwarded TCP connections that are opened after the limit has been hit are
// rejected until the number of in-flight connections drops below the limit
// again.
//
// Each in-flight connection attempt is a new goroutine and an open TCP
// connection, so we want to ensure that we don't allow an unbounded number of
// connections.
func maxInFlightConnectionAttempts() int {
	if n := maxInFlightConnectionAttemptsForTest; n > 0 {
		return n
	}

	if version.IsMobile() {
		return 1024 // previous global value
	}
	switch version.OS() {
	case "linux":
		// On the assumption that most subnet routers deployed in
		// production are running on Linux, we return a higher value.
		//
		// TODO(andrew-d): tune this based on the amount of system
		// memory instead of a fixed limit.
		return 8192
	default:
		// On all other platforms, return a reasonably high value that
		// most users won't hit.
		return 2048
	}
}

// maxInFlightConnectionAttemptsPerClient is the same as
// maxInFlightConnectionAttempts, but applies on a per-client basis
// (i.e. keyed by the remote Tailscale IP).
func maxInFlightConnectionAttemptsPerClient() int {
	if n := maxInFlightConnectionAttemptsPerClientForTest; n > 0 {
		return n
	}

	// For now, allow each individual client at most 2/3rds of the global
	// limit. On all platforms except mobile, this won't be a visible
	// change for users since this limit was added at the same time as we
	// bumped the global limit, above.
	return maxInFlightConnectionAttempts() * 2 / 3
}

var debugNetstack = envknob.RegisterBool("TS_DEBUG_NETSTACK")

var (
	serviceIP   = tsaddr.TailscaleServiceIP()
	serviceIPv6 = tsaddr.TailscaleServiceIPv6()
)

func init() {
	mode := envknob.String("TS_DEBUG_NETSTACK_LEAK_MODE")
	if mode == "" {
		return
	}
	var lm refs.LeakMode
	if err := lm.Set(mode); err != nil {
		panic(err)
	}
	refs.SetLeakMode(lm)
}

// Impl contains the state for the netstack implementation,
// and implements wgengine.FakeImpl to act as a userspace network
// stack when Tailscale is running in fake mode.
type Impl struct {
	// GetTCPHandlerForFlow conditionally handles an incoming TCP flow for the
	// provided (src/port, dst/port) 4-tuple.
	//
	// A nil value is equivalent to a func returning (nil, false).
	//
	// If func returns intercept=false, the default forwarding behavior (if
	// ProcessLocalIPs and/or ProcesssSubnetIPs) takes place.
	//
	// When intercept=true, the behavior depends on whether the returned handler
	// is non-nil: if nil, the connection is rejected. If non-nil, handler takes
	// over the TCP conn.
	GetTCPHandlerForFlow func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool)

	// GetUDPHandlerForFlow conditionally handles an incoming UDP flow for the
	// provided (src/port, dst/port) 4-tuple.
	//
	// A nil value is equivalent to a func returning (nil, false).
	//
	// If func returns intercept=false, the default forwarding behavior (if
	// ProcessLocalIPs and/or ProcesssSubnetIPs) takes place.
	//
	// When intercept=true, the behavior depends on whether the returned handler
	// is non-nil: if nil, the connection is rejected. If non-nil, handler takes
	// over the UDP flow.
	GetUDPHandlerForFlow func(src, dst netip.AddrPort) (handler func(nettype.ConnPacketConn), intercept bool)

	// ProcessLocalIPs is whether netstack should handle incoming
	// traffic directed at the Node.Addresses (local IPs).
	// It can only be set before calling Start.
	ProcessLocalIPs bool

	// ProcessSubnets is whether netstack should handle incoming
	// traffic destined to non-local IPs (i.e. whether it should
	// be a subnet router).
	// It can only be set before calling Start.
	ProcessSubnets bool

	ipstack   *stack.Stack
	linkEP    *linkEndpoint
	tundev    *tstun.Wrapper
	e         wgengine.Engine
	pm        *proxymap.Mapper
	mc        *magicsock.Conn
	logf      logger.Logf
	dialer    *tsdial.Dialer
	ctx       context.Context        // alive until Close
	ctxCancel context.CancelFunc     // called on Close
	lb        *ipnlocal.LocalBackend // or nil
	dns       *dns.Manager

	// loopbackPort, if non-nil, will enable Impl to loop back (dnat to
	// <address-family-loopback>:loopbackPort) TCP & UDP flows originally
	// destined to serviceIP{v6}:loopbackPort.
	loopbackPort *int

	peerapiPort4Atomic atomic.Uint32 // uint16 port number for IPv4 peerapi
	peerapiPort6Atomic atomic.Uint32 // uint16 port number for IPv6 peerapi

	// atomicIsLocalIPFunc holds a func that reports whether an IP
	// is a local (non-subnet) Tailscale IP address of this
	// machine. It's always a non-nil func. It's changed on netmap
	// updates.
	atomicIsLocalIPFunc syncs.AtomicValue[func(netip.Addr) bool]

	atomicIsVIPServiceIPFunc syncs.AtomicValue[func(netip.Addr) bool]

	// forwardDialFunc, if non-nil, is the net.Dialer.DialContext-style
	// function that is used to make outgoing connections when forwarding a
	// TCP connection to another host (e.g. in subnet router mode).
	//
	// This is currently only used in tests.
	forwardDialFunc netx.DialFunc

	// forwardInFlightPerClientDropped is a metric that tracks how many
	// in-flight TCP forward requests were dropped due to the per-client
	// limit.
	forwardInFlightPerClientDropped expvar.Int

	mu sync.Mutex
	// connsOpenBySubnetIP keeps track of number of connections open
	// for each subnet IP temporarily registered on netstack for active
	// TCP connections, so they can be unregistered when connections are
	// closed.
	connsOpenBySubnetIP map[netip.Addr]int
	// connsInFlightByClient keeps track of the number of in-flight
	// connections by the client ("Tailscale") IP. This is used to apply a
	// per-client limit on in-flight connections that's smaller than the
	// global limit, preventing a misbehaving client from starving the
	// global limit.
	connsInFlightByClient map[netip.Addr]int
	// packetsInFlight tracks whether we're already handling a packet by
	// the given endpoint ID; clients can send repeated SYN packets while
	// trying to establish a connection (and while we're dialing the
	// upstream address). If we don't deduplicate based on the endpoint,
	// each SYN retransmit results in us incrementing
	// connsInFlightByClient, and not decrementing them because the
	// underlying TCP forwarder returns 'true' to indicate that the packet
	// is handled but never actually launches our acceptTCP function.
	//
	// This mimics the 'inFlight' map in the TCP forwarder; it's
	// unfortunate that we have to track this all twice, but thankfully the
	// map only holds pending (in-flight) packets, and it's reasonably cheap.
	packetsInFlight map[stack.TransportEndpointID]struct{}
}

const nicID = 1

// maxUDPPacketSize is the maximum size of a UDP packet we copy in
// startPacketCopy when relaying UDP packets. The user can configure
// the tailscale MTU to anything up to this size so we can potentially
// have a UDP packet as big as the MTU.
const maxUDPPacketSize = tstun.MaxPacketSize

func setTCPBufSizes(ipstack *stack.Stack) error {
	// tcpip.TCP{Receive,Send}BufferSizeRangeOption is gVisor's version of
	// Linux's tcp_{r,w}mem. Application within gVisor differs as some Linux
	// features are not (yet) implemented, and socket buffer memory is not
	// controlled within gVisor, e.g. we allocate *stack.PacketBuffer's for the
	// write path within Tailscale. Therefore, we loosen our understanding of
	// the relationship between these Linux and gVisor tunables. The chosen
	// values are biased towards higher throughput on high bandwidth-delay
	// product paths, except on memory-constrained platforms.
	tcpRXBufOpt := tcpip.TCPReceiveBufferSizeRangeOption{
		// Min is unused by gVisor at the time of writing, but partially plumbed
		// for application by the TCP_WINDOW_CLAMP socket option.
		Min: tcpRXBufMinSize,
		// Default is used by gVisor at socket creation.
		Default: tcpRXBufDefSize,
		// Max is used by gVisor to cap the advertised receive window post-read.
		// (tcp_moderate_rcvbuf=true, the default).
		Max: tcpRXBufMaxSize,
	}
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRXBufOpt)
	if tcpipErr != nil {
		return fmt.Errorf("could not set TCP RX buf size: %v", tcpipErr)
	}
	tcpTXBufOpt := tcpip.TCPSendBufferSizeRangeOption{
		// Min in unused by gVisor at the time of writing.
		Min: tcpTXBufMinSize,
		// Default is used by gVisor at socket creation.
		Default: tcpTXBufDefSize,
		// Max is used by gVisor to cap the send window.
		Max: tcpTXBufMaxSize,
	}
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpTXBufOpt)
	if tcpipErr != nil {
		return fmt.Errorf("could not set TCP TX buf size: %v", tcpipErr)
	}
	return nil
}

// Create creates and populates a new Impl.
func Create(logf logger.Logf, tundev *tstun.Wrapper, e wgengine.Engine, mc *magicsock.Conn, dialer *tsdial.Dialer, dns *dns.Manager, pm *proxymap.Mapper) (*Impl, error) {
	if mc == nil {
		return nil, errors.New("nil magicsock.Conn")
	}
	if tundev == nil {
		return nil, errors.New("nil tundev")
	}
	if logf == nil {
		return nil, errors.New("nil logger")
	}
	if e == nil {
		return nil, errors.New("nil Engine")
	}
	if pm == nil {
		return nil, errors.New("nil proxymap.Mapper")
	}
	if dialer == nil {
		return nil, errors.New("nil Dialer")
	}
	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	// See https://github.com/tailscale/tailscale/issues/9707
	// gVisor's RACK performs poorly. ACKs do not appear to be handled in a
	// timely manner, leading to spurious retransmissions and a reduced
	// congestion window.
	tcpRecoveryOpt := tcpip.TCPRecovery(0)
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpRecoveryOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not disable TCP RACK: %v", tcpipErr)
	}
	// gVisor defaults to reno at the time of writing. We explicitly set reno
	// congestion control in order to prevent unexpected changes. Netstack
	// has an int overflow in sender congestion window arithmetic that is more
	// prone to trigger with cubic congestion control.
	// See https://github.com/google/gvisor/issues/11632
	renoOpt := tcpip.CongestionControlOption("reno")
	tcpipErr = ipstack.SetTransportProtocolOption(tcp.ProtocolNumber, &renoOpt)
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not set reno congestion control: %v", tcpipErr)
	}
	err := setTCPBufSizes(ipstack)
	if err != nil {
		return nil, err
	}
	supportedGSOKind := stack.GSONotSupported
	supportedGROKind := groNotSupported
	if runtime.GOOS == "linux" && buildfeatures.HasGRO {
		// TODO(jwhited): add Windows support https://github.com/tailscale/corp/issues/21874
		supportedGROKind = tcpGROSupported
		supportedGSOKind = stack.HostGSOSupported
	}
	linkEP := newLinkEndpoint(512, uint32(tstun.DefaultTUNMTU()), "", supportedGROKind)
	linkEP.SupportedGSOKind = supportedGSOKind
	if tcpipProblem := ipstack.CreateNIC(nicID, linkEP); tcpipProblem != nil {
		return nil, fmt.Errorf("could not create netstack NIC: %v", tcpipProblem)
	}
	// By default the netstack NIC will only accept packets for the IPs
	// registered to it. Since in some cases we dynamically register IPs
	// based on the packets that arrive, the NIC needs to accept all
	// incoming packets. The NIC won't receive anything it isn't meant to
	// since WireGuard will only send us packets that are meant for us.
	ipstack.SetPromiscuousMode(nicID, true)
	// Add IPv4 and IPv6 default routes, so all incoming packets from the Tailscale side
	// are handled by the one fake NIC we use.
	ipv4Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 4)), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		return nil, fmt.Errorf("could not create IPv4 subnet: %v", err)
	}
	ipv6Subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(make([]byte, 16)), tcpip.MaskFromBytes(make([]byte, 16)))
	if err != nil {
		return nil, fmt.Errorf("could not create IPv6 subnet: %v", err)
	}
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})
	ns := &Impl{
		logf:                  logf,
		ipstack:               ipstack,
		linkEP:                linkEP,
		tundev:                tundev,
		e:                     e,
		pm:                    pm,
		mc:                    mc,
		dialer:                dialer,
		connsOpenBySubnetIP:   make(map[netip.Addr]int),
		connsInFlightByClient: make(map[netip.Addr]int),
		packetsInFlight:       make(map[stack.TransportEndpointID]struct{}),
		dns:                   dns,
	}
	loopbackPort, ok := envknob.LookupInt("TS_DEBUG_NETSTACK_LOOPBACK_PORT")
	if ok && loopbackPort >= 0 && loopbackPort <= math.MaxUint16 {
		ns.loopbackPort = &loopbackPort
	}
	ns.ctx, ns.ctxCancel = context.WithCancel(context.Background())
	ns.atomicIsLocalIPFunc.Store(ipset.FalseContainsIPFunc())
	ns.atomicIsVIPServiceIPFunc.Store(ipset.FalseContainsIPFunc())
	ns.tundev.PostFilterPacketInboundFromWireGuard = ns.injectInbound
	ns.tundev.PreFilterPacketOutboundToWireGuardNetstackIntercept = ns.handleLocalPackets
	stacksForMetrics.Store(ns, struct{}{})
	return ns, nil
}

func (ns *Impl) Close() error {
	stacksForMetrics.Delete(ns)
	ns.ctxCancel()
	ns.ipstack.Close()
	ns.ipstack.Wait()
	return nil
}

// SetTransportProtocolOption forwards to the underlying
// [stack.Stack.SetTransportProtocolOption]. Callers are responsible for
// ensuring that the options are valid, compatible and appropriate for their use
// case. Compatibility may change at any version.
func (ns *Impl) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.SettableTransportProtocolOption) tcpip.Error {
	return ns.ipstack.SetTransportProtocolOption(transport, option)
}

// A single process might have several netstacks running at the same time.
// Exported clientmetric counters will have a sum of counters of all of them.
var stacksForMetrics syncs.Map[*Impl, struct{}]

func init() {
	// Please take care to avoid exporting clientmetrics with the same metric
	// names as the ones used by Impl.ExpVar. Both get exposed via the same HTTP
	// endpoint, and name collisions will result in Prometheus scraping errors.
	clientmetric.NewCounterFunc("netstack_tcp_forward_dropped_attempts", func() int64 {
		var total uint64
		for ns := range stacksForMetrics.Keys() {
			delta := ns.ipstack.Stats().TCP.ForwardMaxInFlightDrop.Value()
			if total+delta > math.MaxInt64 {
				total = math.MaxInt64
				break
			}
			total += delta
		}
		return int64(total)
	})
}

type protocolHandlerFunc func(stack.TransportEndpointID, *stack.PacketBuffer) bool

// wrapUDPProtocolHandler wraps the protocol handler we pass to netstack for UDP.
func (ns *Impl) wrapUDPProtocolHandler(h protocolHandlerFunc) protocolHandlerFunc {
	return func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) bool {
		addr := tei.LocalAddress
		ip, ok := netip.AddrFromSlice(addr.AsSlice())
		if !ok {
			ns.logf("netstack: could not parse local address for incoming connection")
			return false
		}

		// Dynamically reconfigure ns's subnet addresses as needed for
		// outbound traffic.
		ip = ip.Unmap()
		if !ns.isLocalIP(ip) {
			ns.addSubnetAddress(ip)
		}
		return h(tei, pb)
	}
}

var (
	metricPerClientForwardLimit = clientmetric.NewCounter("netstack_tcp_forward_dropped_attempts_per_client")
)

// wrapTCPProtocolHandler wraps the protocol handler we pass to netstack for TCP.
func (ns *Impl) wrapTCPProtocolHandler(h protocolHandlerFunc) protocolHandlerFunc {
	// 'handled' is whether the packet should be accepted by netstack; if
	// true, then the TCP connection is accepted by the transport layer and
	// passes through our acceptTCP handler/etc. If false, then the packet
	// is dropped and the TCP connection is rejected (typically with an
	// ICMP Port Unreachable or ICMP Protocol Unreachable message).
	return func(tei stack.TransportEndpointID, pb *stack.PacketBuffer) (handled bool) {
		localIP, ok := netip.AddrFromSlice(tei.LocalAddress.AsSlice())
		if !ok {
			ns.logf("netstack: could not parse local address for incoming connection")
			return false
		}
		localIP = localIP.Unmap()

		remoteIP, ok := netip.AddrFromSlice(tei.RemoteAddress.AsSlice())
		if !ok {
			ns.logf("netstack: could not parse remote address for incoming connection")
			return false
		}

		// If we have too many in-flight connections for this client, abort
		// early and don't open a new one.
		//
		// NOTE: the counter is decremented in
		// decrementInFlightTCPForward, called from the acceptTCP
		// function, below.

		ns.mu.Lock()
		if _, ok := ns.packetsInFlight[tei]; ok {
			// We're already handling this packet; just bail early
			// (this is also what would happen in the TCP
			// forwarder).
			ns.mu.Unlock()
			return true
		}

		// Check the per-client limit.
		inFlight := ns.connsInFlightByClient[remoteIP]
		tooManyInFlight := inFlight >= maxInFlightConnectionAttemptsPerClient()
		if !tooManyInFlight {
			ns.connsInFlightByClient[remoteIP]++
		}

		// We're handling this packet now; see the comment on the
		// packetsInFlight field for more details.
		ns.packetsInFlight[tei] = struct{}{}
		ns.mu.Unlock()

		if debugNetstack() {
			ns.logf("[v2] netstack: in-flight connections for client %v: %d", remoteIP, inFlight)
		}
		if tooManyInFlight {
			ns.logf("netstack: ignoring a new TCP connection from %v to %v because the client already has %d in-flight connections", localIP, remoteIP, inFlight)
			metricPerClientForwardLimit.Add(1)
			ns.forwardInFlightPerClientDropped.Add(1)
			return false // unhandled
		}

		// On return, if this packet isn't handled by the inner handler
		// we're wrapping (`h`), we need to decrement the per-client
		// in-flight count and remove the ID from our tracking map.
		// This can happen if the underlying forwarder's limit has been
		// reached, at which point it will return false to indicate
		// that it's not handling the packet, and it will not run
		// acceptTCP.  If we don't decrement here, then we would
		// eventually increment the per-client counter up to the limit
		// and never decrement because we'd never hit the codepath in
		// acceptTCP, below, or just drop all packets from the same
		// endpoint due to the packetsInFlight check.
		defer func() {
			if !handled {
				ns.mu.Lock()
				delete(ns.packetsInFlight, tei)
				ns.connsInFlightByClient[remoteIP]--
				new := ns.connsInFlightByClient[remoteIP]
				ns.mu.Unlock()
				ns.logf("netstack: decrementing connsInFlightByClient[%v] because the packet was not handled; new value is %d", remoteIP, new)
			}
		}()

		// Dynamically reconfigure ns's subnet addresses as needed for
		// outbound traffic.
		if !ns.isLocalIP(localIP) && !ns.isVIPServiceIP(localIP) {
			ns.addSubnetAddress(localIP)
		}

		return h(tei, pb)
	}
}

func (ns *Impl) decrementInFlightTCPForward(tei stack.TransportEndpointID, remoteAddr netip.Addr) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Remove this packet so future SYNs from this address will be handled.
	delete(ns.packetsInFlight, tei)

	was := ns.connsInFlightByClient[remoteAddr]
	newVal := was - 1
	if newVal == 0 {
		delete(ns.connsInFlightByClient, remoteAddr) // free up space in the map
	} else {
		ns.connsInFlightByClient[remoteAddr] = newVal
	}
}

// LocalBackend is a fake name for *ipnlocal.LocalBackend to avoid an import cycle.
type LocalBackend = any

// Start sets up all the handlers so netstack can start working. Implements
// wgengine.FakeImpl.
func (ns *Impl) Start(b LocalBackend) error {
	if b == nil {
		panic("nil LocalBackend interface")
	}
	lb := b.(*ipnlocal.LocalBackend)
	if lb == nil {
		panic("nil LocalBackend")
	}
	ns.lb = lb
	tcpFwd := tcp.NewForwarder(ns.ipstack, tcpRXBufDefSize, maxInFlightConnectionAttempts(), ns.acceptTCP)
	udpFwd := udp.NewForwarder(ns.ipstack, ns.acceptUDP)
	ns.ipstack.SetTransportProtocolHandler(tcp.ProtocolNumber, ns.wrapTCPProtocolHandler(tcpFwd.HandlePacket))
	ns.ipstack.SetTransportProtocolHandler(udp.ProtocolNumber, ns.wrapUDPProtocolHandler(udpFwd.HandlePacket))
	go ns.inject()
	return nil
}

func (ns *Impl) addSubnetAddress(ip netip.Addr) {
	ns.mu.Lock()
	ns.connsOpenBySubnetIP[ip]++
	needAdd := ns.connsOpenBySubnetIP[ip] == 1
	ns.mu.Unlock()
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
		ns.ipstack.AddProtocolAddress(nicID, pa, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
	}
}

func (ns *Impl) removeSubnetAddress(ip netip.Addr) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.connsOpenBySubnetIP[ip]--
	// Only unregister address from netstack after last concurrent connection.
	if ns.connsOpenBySubnetIP[ip] == 0 {
		ns.ipstack.RemoveAddress(nicID, tcpip.AddrFromSlice(ip.AsSlice()))
		delete(ns.connsOpenBySubnetIP, ip)
	}
}

func ipPrefixToAddressWithPrefix(ipp netip.Prefix) tcpip.AddressWithPrefix {
	return tcpip.AddressWithPrefix{
		Address:   tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		PrefixLen: int(ipp.Bits()),
	}
}

var v4broadcast = netaddr.IPv4(255, 255, 255, 255)

// UpdateNetstackIPs updates the set of local IPs that netstack should handle
// from nm.
//
// TODO(bradfitz): don't pass the whole netmap here; just pass the two
// address slice views.
func (ns *Impl) UpdateNetstackIPs(nm *netmap.NetworkMap) {
	var selfNode tailcfg.NodeView
	var serviceAddrSet set.Set[netip.Addr]
	if nm != nil {
		ns.atomicIsLocalIPFunc.Store(ipset.NewContainsIPFunc(nm.GetAddresses()))
		if buildfeatures.HasServe {
			vipServiceIPMap := nm.GetVIPServiceIPMap()
			serviceAddrSet = make(set.Set[netip.Addr], len(vipServiceIPMap)*2)
			for _, addrs := range vipServiceIPMap {
				serviceAddrSet.AddSlice(addrs)
			}
			ns.atomicIsVIPServiceIPFunc.Store(serviceAddrSet.Contains)
		}
		selfNode = nm.SelfNode
	} else {
		ns.atomicIsLocalIPFunc.Store(ipset.FalseContainsIPFunc())
		ns.atomicIsVIPServiceIPFunc.Store(ipset.FalseContainsIPFunc())
	}

	oldPfx := make(map[netip.Prefix]bool)
	for _, protocolAddr := range ns.ipstack.AllAddresses()[nicID] {
		ap := protocolAddr.AddressWithPrefix
		ip := netaddrIPFromNetstackIP(ap.Address)
		if ip == v4broadcast && ap.PrefixLen == 32 {
			// Don't add 255.255.255.255/32 to oldIPs so we don't
			// delete it later. We didn't install it, so it's not
			// ours to delete.
			continue
		}
		p := netip.PrefixFrom(ip, ap.PrefixLen)
		oldPfx[p] = true
	}
	newPfx := make(map[netip.Prefix]bool)

	if selfNode.Valid() {
		for _, p := range selfNode.Addresses().All() {
			newPfx[p] = true
		}
		if ns.ProcessSubnets {
			for _, p := range selfNode.AllowedIPs().All() {
				newPfx[p] = true
			}
		}
	}

	for addr := range serviceAddrSet {
		p := netip.PrefixFrom(addr, addr.BitLen())
		newPfx[p] = true
	}

	pfxToAdd := make(map[netip.Prefix]bool)
	for p := range newPfx {
		if !oldPfx[p] {
			pfxToAdd[p] = true
		}
	}
	pfxToRemove := make(map[netip.Prefix]bool)
	for p := range oldPfx {
		if !newPfx[p] {
			pfxToRemove[p] = true
		}
	}
	ns.mu.Lock()
	for ip := range ns.connsOpenBySubnetIP {
		// TODO(maisem): this looks like a bug, remove or document. It seems as
		// though we might end up either leaking the address on the netstack
		// NIC, or where we do accounting for connsOpenBySubnetIP from 1 to 0,
		// we might end up removing the address from the netstack NIC that was
		// still being advertised.
		delete(pfxToRemove, netip.PrefixFrom(ip, ip.BitLen()))
	}
	ns.mu.Unlock()

	for p := range pfxToRemove {
		err := ns.ipstack.RemoveAddress(nicID, tcpip.AddrFromSlice(p.Addr().AsSlice()))
		if err != nil {
			ns.logf("netstack: could not deregister IP %s: %v", p, err)
		} else {
			ns.logf("[v2] netstack: deregistered IP %s", p)
		}
	}
	for p := range pfxToAdd {
		if !p.IsValid() {
			ns.logf("netstack: [unexpected] skipping invalid IP (%v/%v)", p.Addr(), p.Bits())
			continue
		}
		tcpAddr := tcpip.ProtocolAddress{
			AddressWithPrefix: ipPrefixToAddressWithPrefix(p),
		}
		if p.Addr().Is6() {
			tcpAddr.Protocol = ipv6.ProtocolNumber
		} else {
			tcpAddr.Protocol = ipv4.ProtocolNumber
		}
		var tcpErr tcpip.Error // not error
		tcpErr = ns.ipstack.AddProtocolAddress(nicID, tcpAddr, stack.AddressProperties{
			PEB:        stack.CanBePrimaryEndpoint, // zero value default
			ConfigType: stack.AddressConfigStatic,  // zero value default
		})
		if tcpErr != nil {
			ns.logf("netstack: could not register IP %s: %v", p, tcpErr)
		} else {
			ns.logf("[v2] netstack: registered IP %s", p)
		}
	}
}

func (ns *Impl) isLoopbackPort(port uint16) bool {
	if ns.loopbackPort != nil && int(port) == *ns.loopbackPort {
		return true
	}
	return false
}

// handleLocalPackets is hooked into the tun datapath for packets leaving
// the host and arriving at tailscaled. This method returns filter.DropSilently
// to intercept a packet for handling, for instance traffic to quad-100.
func (ns *Impl) handleLocalPackets(p *packet.Parsed, t *tstun.Wrapper, gro *gro.GRO) (filter.Response, *gro.GRO) {
	if ns.ctx.Err() != nil {
		return filter.DropSilently, gro
	}

	// Determine if we care about this local packet.
	dst := p.Dst.Addr()
	switch {
	case dst == serviceIP || dst == serviceIPv6:
		// We want to intercept some traffic to the "service IP" (e.g.
		// 100.100.100.100 for IPv4). However, of traffic to the
		// service IP, we only care about UDP 53, and TCP on port 53,
		// 80, and 8080.
		switch p.IPProto {
		case ipproto.TCP:
			if port := p.Dst.Port(); port != 53 && port != 80 && port != 8080 && !ns.isLoopbackPort(port) {
				return filter.Accept, gro
			}
		case ipproto.UDP:
			if port := p.Dst.Port(); port != 53 && !ns.isLoopbackPort(port) {
				return filter.Accept, gro
			}
		}
	case viaRange.Contains(dst):
		// We need to handle 4via6 packets leaving the host if the via
		// route is for this host; otherwise the packet will be dropped
		// because nothing will translate it.
		var shouldHandle bool
		if p.IPVersion == 6 && !ns.isLocalIP(dst) {
			shouldHandle = ns.lb != nil && ns.lb.ShouldHandleViaIP(dst)
		}
		if !shouldHandle {
			// Unhandled means that we let the regular processing
			// occur without doing anything ourselves.
			return filter.Accept, gro
		}

		if debugNetstack() {
			ns.logf("netstack: handling local 4via6 packet: version=%d proto=%v dst=%v src=%v",
				p.IPVersion, p.IPProto, p.Dst, p.Src)
		}

		// If this is a ping message, handle it and don't pass to
		// netstack.
		pingIP, handlePing := ns.shouldHandlePing(p)
		if handlePing {
			ns.logf("netstack: handling local 4via6 ping: dst=%v pingIP=%v", dst, pingIP)

			var pong []byte // the reply to the ping, if our relayed ping works
			if dst.Is4() {
				h := p.ICMP4Header()
				h.ToResponse()
				pong = packet.Generate(&h, p.Payload())
			} else if dst.Is6() {
				h := p.ICMP6Header()
				h.ToResponse()
				pong = packet.Generate(&h, p.Payload())
			}

			go ns.userPing(pingIP, pong, userPingDirectionInbound)
			return filter.DropSilently, gro
		}

		// Fall through to writing inbound so netstack handles the
		// 4via6 via connection.

	default:
		// Not traffic to the service IP or a 4via6 IP, so we don't
		// care about the packet; resume processing.
		return filter.Accept, gro
	}
	if debugPackets {
		ns.logf("[v2] service packet in (from %v): % x", p.Src, p.Buffer())
	}

	gro = ns.linkEP.gro(p, gro)
	return filter.DropSilently, gro
}

func (ns *Impl) DialContextTCP(ctx context.Context, ipp netip.AddrPort) (*gonet.TCPConn, error) {
	remoteAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialContextTCP(ctx, ns.ipstack, remoteAddress, ipType)
}

// DialContextTCPWithBind creates a new gonet.TCPConn connected to the specified
// remoteAddress with its local address bound to localAddr on an available port.
func (ns *Impl) DialContextTCPWithBind(ctx context.Context, localAddr netip.Addr, remoteAddr netip.AddrPort) (*gonet.TCPConn, error) {
	remoteAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(remoteAddr.Addr().AsSlice()),
		Port: remoteAddr.Port(),
	}
	localAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(localAddr.AsSlice()),
	}
	var ipType tcpip.NetworkProtocolNumber
	if remoteAddr.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}
	return gonet.DialTCPWithBind(ctx, ns.ipstack, localAddress, remoteAddress, ipType)
}

func (ns *Impl) DialContextUDP(ctx context.Context, ipp netip.AddrPort) (*gonet.UDPConn, error) {
	remoteAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ipp.Addr().AsSlice()),
		Port: ipp.Port(),
	}
	var ipType tcpip.NetworkProtocolNumber
	if ipp.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialUDP(ns.ipstack, nil, remoteAddress, ipType)
}

// DialContextUDPWithBind creates a new gonet.UDPConn. Connected to remoteAddr.
// With its local address bound to localAddr on an available port.
func (ns *Impl) DialContextUDPWithBind(ctx context.Context, localAddr netip.Addr, remoteAddr netip.AddrPort) (*gonet.UDPConn, error) {
	remoteAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(remoteAddr.Addr().AsSlice()),
		Port: remoteAddr.Port(),
	}
	localAddress := &tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(localAddr.AsSlice()),
	}
	var ipType tcpip.NetworkProtocolNumber
	if remoteAddr.Addr().Is4() {
		ipType = ipv4.ProtocolNumber
	} else {
		ipType = ipv6.ProtocolNumber
	}

	return gonet.DialUDP(ns.ipstack, localAddress, remoteAddress, ipType)
}

// getInjectInboundBuffsSizes returns packet memory and a sizes slice for usage
// when calling tstun.Wrapper.InjectInboundPacketBuffer(). These are sized with
// consideration for MTU and GSO support on ns.linkEP. They should be recycled
// across subsequent inbound packet injection calls.
func (ns *Impl) getInjectInboundBuffsSizes() (buffs [][]byte, sizes []int) {
	batchSize := 1
	gsoEnabled := ns.linkEP.SupportedGSO() == stack.HostGSOSupported
	if gsoEnabled {
		batchSize = conn.IdealBatchSize
	}
	buffs = make([][]byte, batchSize)
	sizes = make([]int, batchSize)
	for i := 0; i < batchSize; i++ {
		if i == 0 && gsoEnabled {
			buffs[i] = make([]byte, tstun.PacketStartOffset+ns.linkEP.GSOMaxSize())
		} else {
			buffs[i] = make([]byte, tstun.PacketStartOffset+tstun.DefaultTUNMTU())
		}
	}
	return buffs, sizes
}

// The inject goroutine reads in packets that netstack generated, and delivers
// them to the correct path.
func (ns *Impl) inject() {
	inboundBuffs, inboundBuffsSizes := ns.getInjectInboundBuffsSizes()
	for {
		pkt := ns.linkEP.ReadContext(ns.ctx)
		if pkt == nil {
			if ns.ctx.Err() != nil {
				// Return without logging.
				return
			}
			ns.logf("[v2] ReadContext-for-write = ok=false")
			continue
		}

		if debugPackets {
			ns.logf("[v2] packet Write out: % x", stack.PayloadSince(pkt.NetworkHeader()).AsSlice())
		}

		// In the normal case, netstack synthesizes the bytes for
		// traffic which should transit back into WG and go to peers.
		// However, some uses of netstack (presently, magic DNS)
		// send traffic destined for the local device, hence must
		// be injected 'inbound'.
		sendToHost := ns.shouldSendToHost(pkt)

		// pkt has a non-zero refcount, so injection methods takes
		// ownership of one count and will decrement on completion.
		if sendToHost {
			if err := ns.tundev.InjectInboundPacketBuffer(pkt, inboundBuffs, inboundBuffsSizes); err != nil {
				ns.logf("netstack inject inbound: %v", err)
				return
			}
		} else {
			if err := ns.tundev.InjectOutboundPacketBuffer(pkt); err != nil {
				ns.logf("netstack inject outbound: %v", err)
				return
			}
		}
	}
}

// shouldSendToHost determines if the provided packet should be sent to the
// host (i.e the current machine running Tailscale), in which case it will
// return true. It will return false if the packet should be sent outbound, for
// transit via WireGuard to another Tailscale node.
func (ns *Impl) shouldSendToHost(pkt *stack.PacketBuffer) bool {
	// Determine if the packet is from a service IP (100.100.100.100 or the
	// IPv6 variant), in which case it needs to go back into the machine's
	// network (inbound) instead of out.
	hdr := pkt.Network()
	switch v := hdr.(type) {
	case header.IPv4:
		srcIP := netip.AddrFrom4(v.SourceAddress().As4())
		if serviceIP == srcIP {
			return true
		}

	case header.IPv6:
		srcIP := netip.AddrFrom16(v.SourceAddress().As16())
		if srcIP == serviceIPv6 {
			return true
		}

		if viaRange.Contains(srcIP) {
			// Only send to the host if this 4via6 route is
			// something this node handles.
			if ns.lb != nil && ns.lb.ShouldHandleViaIP(srcIP) {
				dstIP := netip.AddrFrom16(v.DestinationAddress().As16())
				// Also, only forward to the host if the packet
				// is destined for a local IP; otherwise, we'd
				// send traffic that's intended for another
				// peer from the local 4via6 address to the
				// host instead of outbound to WireGuard. See:
				//     https://github.com/tailscale/tailscale/issues/12448
				if ns.isLocalIP(dstIP) {
					return true
				}
				if debugNetstack() {
					ns.logf("netstack: sending 4via6 packet to host: src=%v dst=%v", srcIP, dstIP)
				}
			}
		}
	default:
		// unknown; don't forward to host
		if debugNetstack() {
			ns.logf("netstack: unexpected packet in shouldSendToHost: %T", v)
		}
	}

	return false
}

// isLocalIP reports whether ip is a Tailscale IP assigned to this
// node directly (but not a subnet-routed IP).
func (ns *Impl) isLocalIP(ip netip.Addr) bool {
	return ns.atomicIsLocalIPFunc.Load()(ip)
}

// isVIPServiceIP reports whether ip is an IP address that's
// assigned to a VIP service.
func (ns *Impl) isVIPServiceIP(ip netip.Addr) bool {
	if !buildfeatures.HasServe {
		return false
	}
	return ns.atomicIsVIPServiceIPFunc.Load()(ip)
}

func (ns *Impl) peerAPIPortAtomic(ip netip.Addr) *atomic.Uint32 {
	if ip.Is4() {
		return &ns.peerapiPort4Atomic
	} else {
		return &ns.peerapiPort6Atomic
	}
}

var viaRange = tsaddr.TailscaleViaRange()

// shouldProcessInbound reports whether an inbound packet (a packet from a
// WireGuard peer) should be handled by netstack.
func (ns *Impl) shouldProcessInbound(p *packet.Parsed, t *tstun.Wrapper) bool {
	// Handle incoming peerapi connections in netstack.
	dstIP := p.Dst.Addr()
	isLocal := ns.isLocalIP(dstIP)
	isService := ns.isVIPServiceIP(dstIP)

	// Handle TCP connection to the Tailscale IP(s) in some cases:
	if ns.lb != nil && p.IPProto == ipproto.TCP && isLocal {
		var peerAPIPort uint16

		if p.TCPFlags&packet.TCPSynAck == packet.TCPSyn {
			if port, ok := ns.lb.GetPeerAPIPort(dstIP); ok {
				peerAPIPort = port
				ns.peerAPIPortAtomic(dstIP).Store(uint32(port))
			}
		} else {
			peerAPIPort = uint16(ns.peerAPIPortAtomic(dstIP).Load())
		}
		dport := p.Dst.Port()
		if dport == peerAPIPort {
			return true
		}
		// Also handle SSH connections, webserver, etc, if enabled:
		if ns.lb.ShouldInterceptTCPPort(dport) {
			return true
		}
	}
	if buildfeatures.HasServe && isService {
		if p.IsEchoRequest() {
			return true
		}
		if ns.lb != nil && p.IPProto == ipproto.TCP {
			// An assumption holds for this to work: when tun mode is on for a service,
			// its tcp and web are not set. This is enforced in b.setServeConfigLocked.
			if ns.lb.ShouldInterceptVIPServiceTCPPort(p.Dst) {
				return true
			}
		}
		return false
	}
	if p.IPVersion == 6 && !isLocal && viaRange.Contains(dstIP) {
		return ns.lb != nil && ns.lb.ShouldHandleViaIP(dstIP)
	}
	if ns.ProcessLocalIPs && isLocal {
		return true
	}
	if ns.ProcessSubnets && !isLocal {
		return true
	}
	return false
}

var userPingSem = syncs.NewSemaphore(20) // 20 child ping processes at once

type userPingDirection int

const (
	// userPingDirectionOutbound is used when the pong packet is to be sent
	// "outbound"–i.e. from this node to a peer via WireGuard.
	userPingDirectionOutbound userPingDirection = iota
	// userPingDirectionInbound is used when the pong packet is to be sent
	// "inbound"–i.e. from Tailscale to another process on this host.
	userPingDirectionInbound
)

// userPing tried to ping dstIP and if it succeeds, injects pingResPkt
// into the tundev.
//
// It's used in userspace/netstack mode when we don't have kernel
// support or raw socket access. As such, this does the dumbest thing
// that can work: runs the ping command. It's not super efficient, so
// it bounds the number of pings going on at once. The idea is that
// people only use ping occasionally to see if their internet's working
// so this doesn't need to be great.
// On Apple platforms, this function doesn't run the ping command. Instead,
// it sends a non-privileged ping.
//
// The 'direction' parameter is used to determine where the response "pong"
// packet should be written, if the ping succeeds. See the documentation on the
// constants for more details.
//
// TODO(bradfitz): when we're running on Windows as the system user, use
// raw socket APIs instead of ping child processes.
func (ns *Impl) userPing(dstIP netip.Addr, pingResPkt []byte, direction userPingDirection) {
	if !userPingSem.TryAcquire() {
		return
	}
	defer userPingSem.Release()

	t0 := time.Now()
	err := ns.sendOutboundUserPing(dstIP, 3*time.Second)
	d := time.Since(t0)
	if err != nil {
		if d < time.Second/2 {
			// If it failed quicker than the 3 second
			// timeout we gave above (500 ms is a
			// reasonable threshold), then assume the ping
			// failed for problems finding/running
			// ping. We don't want to log if the host is
			// just down.
			ns.logf("exec ping of %v failed in %v: %v", dstIP, d, err)
		}
		return
	}
	if debugNetstack() {
		ns.logf("exec pinged %v in %v", dstIP, time.Since(t0))
	}
	if direction == userPingDirectionOutbound {
		if err := ns.tundev.InjectOutbound(pingResPkt); err != nil {
			ns.logf("InjectOutbound ping response: %v", err)
		}
	} else if direction == userPingDirectionInbound {
		if err := ns.tundev.InjectInboundCopy(pingResPkt); err != nil {
			ns.logf("InjectInboundCopy ping response: %v", err)
		}
	}
}

// injectInbound is installed as a packet hook on the 'inbound' (from a
// WireGuard peer) path. Returning filter.Accept releases the packet to
// continue normally (typically being delivered to the host networking stack),
// whereas returning filter.DropSilently is done when netstack intercepts the
// packet and no further processing towards to host should be done.
func (ns *Impl) injectInbound(p *packet.Parsed, t *tstun.Wrapper, gro *gro.GRO) (filter.Response, *gro.GRO) {
	if ns.ctx.Err() != nil {
		return filter.DropSilently, gro
	}

	if !ns.shouldProcessInbound(p, t) {
		// Let the host network stack (if any) deal with it.
		return filter.Accept, gro
	}

	destIP := p.Dst.Addr()

	// If this is an echo request and we're a subnet router, handle pings
	// ourselves instead of forwarding the packet on.
	pingIP, handlePing := ns.shouldHandlePing(p)
	if handlePing {
		var pong []byte // the reply to the ping, if our relayed ping works
		if destIP.Is4() {
			h := p.ICMP4Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		} else if destIP.Is6() {
			h := p.ICMP6Header()
			h.ToResponse()
			pong = packet.Generate(&h, p.Payload())
		}
		go ns.userPing(pingIP, pong, userPingDirectionOutbound)
		return filter.DropSilently, gro
	}

	if debugPackets {
		ns.logf("[v2] packet in (from %v): % x", p.Src, p.Buffer())
	}
	gro = ns.linkEP.gro(p, gro)

	// We've now delivered this to netstack, so we're done.
	// Instead of returning a filter.Accept here (which would also
	// potentially deliver it to the host OS), and instead of
	// filter.Drop (which would log about rejected traffic),
	// instead return filter.DropSilently which just quietly stops
	// processing it in the tstun TUN wrapper.
	return filter.DropSilently, gro
}

// shouldHandlePing returns whether or not netstack should handle an incoming
// ICMP echo request packet, and the IP address that should be pinged from this
// process. The IP address can be different from the destination in the packet
// if the destination is a 4via6 address.
func (ns *Impl) shouldHandlePing(p *packet.Parsed) (_ netip.Addr, ok bool) {
	if !p.IsEchoRequest() {
		return netip.Addr{}, false
	}

	destIP := p.Dst.Addr()

	// We need to handle pings for all 4via6 addresses, even if this
	// netstack instance normally isn't responsible for processing subnets.
	//
	// For example, on Linux, subnet router traffic could be handled via
	// tun+iptables rules for most packets, but we still need to handle
	// ICMP echo requests over 4via6 since the host networking stack
	// doesn't know what to do with a 4via6 address.
	//
	// shouldProcessInbound returns 'true' to say that we should process
	// all IPv6 packets with a destination address in the 'via' range, so
	// check before we check the "ProcessSubnets" boolean below.
	if viaRange.Contains(destIP) {
		// The input echo request was to a 4via6 address, which we cannot
		// simply ping as-is from this process. Translate the destination to an
		// IPv4 address, so that our relayed ping (in userPing) is pinging the
		// underlying destination IP.
		//
		// ICMPv4 and ICMPv6 are different protocols with different on-the-wire
		// representations, so normally you can't send an ICMPv6 message over
		// IPv4 and expect to get a useful result. However, in this specific
		// case things are safe because the 'userPing' function doesn't make
		// use of the input packet.
		return tsaddr.UnmapVia(destIP), true
	}

	// If we get here, we don't do anything unless this netstack instance
	// is responsible for processing subnet traffic.
	if !ns.ProcessSubnets {
		return netip.Addr{}, false
	}

	// For non-4via6 addresses, we don't handle pings if they're destined
	// for a Tailscale IP.
	if tsaddr.IsTailscaleIP(destIP) {
		return netip.Addr{}, false
	}

	// This netstack instance is processing subnet traffic, so handle the
	// ping ourselves.
	return destIP, true
}

func netaddrIPFromNetstackIP(s tcpip.Address) netip.Addr {
	switch s.Len() {
	case 4:
		return netip.AddrFrom4(s.As4())
	case 16:
		return netip.AddrFrom16(s.As16()).Unmap()
	}
	return netip.Addr{}
}

var (
	ipv4Loopback = netip.MustParseAddr("127.0.0.1")
	ipv6Loopback = netip.MustParseAddr("::1")
)

func (ns *Impl) acceptTCP(r *tcp.ForwarderRequest) {
	reqDetails := r.ID()
	if debugNetstack() {
		ns.logf("[v2] TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
	}
	clientRemoteIP := netaddrIPFromNetstackIP(reqDetails.RemoteAddress)
	if !clientRemoteIP.IsValid() {
		ns.logf("invalid RemoteAddress in TCP ForwarderRequest: %s", stringifyTEI(reqDetails))
		r.Complete(true) // sends a RST
		return
	}

	// After we've returned from this function or have otherwise reached a
	// non-pending state, decrement the per-client in-flight count and
	// remove this endpoint from our packet tracking map so future TCP
	// connections aren't dropped.
	inFlightCompleted := false
	tei := r.ID()
	defer func() {
		if !inFlightCompleted {
			ns.decrementInFlightTCPForward(tei, clientRemoteIP)
		}
	}()

	clientRemotePort := reqDetails.RemotePort
	clientRemoteAddrPort := netip.AddrPortFrom(clientRemoteIP, clientRemotePort)

	dialIP := netaddrIPFromNetstackIP(reqDetails.LocalAddress)
	isTailscaleIP := tsaddr.IsTailscaleIP(dialIP)

	dstAddrPort := netip.AddrPortFrom(dialIP, reqDetails.LocalPort)

	if viaRange.Contains(dialIP) {
		isTailscaleIP = false
		dialIP = tsaddr.UnmapVia(dialIP)
	}

	defer func() {
		if !isTailscaleIP {
			// if this is a subnet IP, we added this in before the TCP handshake
			// so netstack is happy TCP-handshaking as a subnet IP
			ns.removeSubnetAddress(dialIP)
		}
	}()

	var wq waiter.Queue

	// We can't actually create the endpoint or complete the inbound
	// request until we're sure that the connection can be handled by this
	// endpoint. This function sets up the TCP connection and should be
	// called immediately before a connection is handled.
	getConnOrReset := func(opts ...tcpip.SettableSocketOption) *gonet.TCPConn {
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			ns.logf("CreateEndpoint error for %s: %v", stringifyTEI(reqDetails), err)
			r.Complete(true) // sends a RST
			return nil
		}
		r.Complete(false)
		for _, opt := range opts {
			ep.SetSockOpt(opt)
		}
		// SetKeepAlive so that idle connections to peers that have forgotten about
		// the connection or gone completely offline eventually time out.
		// Applications might be setting this on a forwarded connection, but from
		// userspace we can not see those, so the best we can do is to always
		// perform them with conservative timing.
		// TODO(tailscale/tailscale#4522): Netstack defaults match the Linux
		// defaults, and results in a little over two hours before the socket would
		// be closed due to keepalive. A shorter default might be better, or seeking
		// a default from the host IP stack. This also might be a useful
		// user-tunable, as in userspace mode this can have broad implications such
		// as lingering connections to fork style daemons. On the other side of the
		// fence, the long duration timers are low impact values for battery powered
		// peers.
		ep.SocketOptions().SetKeepAlive(true)

		// This function is called when we're ready to use the
		// underlying connection, and thus it's no longer in a
		// "in-flight" state; decrement our per-client limit right now,
		// and tell the defer in acceptTCP that it doesn't need to do
		// so upon return.
		ns.decrementInFlightTCPForward(tei, clientRemoteIP)
		inFlightCompleted = true

		// The ForwarderRequest.CreateEndpoint above asynchronously
		// starts the TCP handshake. Note that the gonet.TCPConn
		// methods c.RemoteAddr() and c.LocalAddr() will return nil
		// until the handshake actually completes. But we have the
		// remote address in reqDetails instead, so we don't use
		// gonet.TCPConn.RemoteAddr. The byte copies in both
		// directions to/from the gonet.TCPConn in forwardTCP will
		// block until the TCP handshake is complete.
		return gonet.NewTCPConn(&wq, ep)
	}

	// Local Services (DNS and WebDAV)
	hittingServiceIP := dialIP == serviceIP || dialIP == serviceIPv6
	hittingDNS := hittingServiceIP && reqDetails.LocalPort == 53
	if hittingDNS {
		c := getConnOrReset()
		if c == nil {
			return
		}
		addrPort := netip.AddrPortFrom(clientRemoteIP, reqDetails.RemotePort)
		go ns.dns.HandleTCPConn(c, addrPort)
		return
	}

	if ns.lb != nil {
		handler, opts := ns.lb.TCPHandlerForDst(clientRemoteAddrPort, dstAddrPort)
		if handler != nil {
			c := getConnOrReset(opts...) // will send a RST if it fails
			if c == nil {
				return
			}
			handler(c)
			return
		}
	}

	if ns.GetTCPHandlerForFlow != nil {
		handler, ok := ns.GetTCPHandlerForFlow(clientRemoteAddrPort, dstAddrPort)
		if ok {
			if handler == nil {
				r.Complete(true)
				return
			}
			c := getConnOrReset() // will send a RST if it fails
			if c == nil {
				return
			}
			handler(c)
			return
		}
	}
	switch {
	case hittingServiceIP && ns.isLoopbackPort(reqDetails.LocalPort):
		if dialIP == serviceIPv6 {
			dialIP = ipv6Loopback
		} else {
			dialIP = ipv4Loopback
		}
	case isTailscaleIP:
		dialIP = ipv4Loopback
	}
	dialAddr := netip.AddrPortFrom(dialIP, uint16(reqDetails.LocalPort))

	if !ns.forwardTCP(getConnOrReset, clientRemoteIP, &wq, dialAddr) {
		r.Complete(true) // sends a RST
	}
}

// tcpCloser is an interface to abstract around various TCPConn types that
// allow closing of the read and write streams independently of each other.
type tcpCloser interface {
	CloseRead() error
	CloseWrite() error
}

func (ns *Impl) forwardTCP(getClient func(...tcpip.SettableSocketOption) *gonet.TCPConn, clientRemoteIP netip.Addr, wq *waiter.Queue, dialAddr netip.AddrPort) (handled bool) {
	dialAddrStr := dialAddr.String()
	if debugNetstack() {
		ns.logf("[v2] netstack: forwarding incoming connection to %s", dialAddrStr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp) // TODO(bradfitz): right EventMask?
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	// netstack doesn't close the notification channel automatically if there was no
	// hup signal, so we close done after we're done to not leak the goroutine below.
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
			if debugNetstack() {
				ns.logf("[v2] netstack: forwardTCP notifyCh fired; canceling context for %s", dialAddrStr)
			}
		case <-done:
		}
		cancel()
	}()

	// Attempt to dial the outbound connection before we accept the inbound one.
	var dialFunc netx.DialFunc
	if ns.forwardDialFunc != nil {
		dialFunc = ns.forwardDialFunc
	} else {
		var stdDialer net.Dialer
		dialFunc = stdDialer.DialContext
	}

	// TODO: this is racy, dialing before we register our local address. See
	// https://github.com/tailscale/tailscale/issues/1616.
	backend, err := dialFunc(ctx, "tcp", dialAddrStr)
	if err != nil {
		ns.logf("netstack: could not connect to local backend server at %s: %v", dialAddr.String(), err)
		return
	}
	defer backend.Close()

	backendLocalAddr := backend.LocalAddr().(*net.TCPAddr)
	backendLocalIPPort := netaddr.Unmap(backendLocalAddr.AddrPort())
	if err := ns.pm.RegisterIPPortIdentity("tcp", backendLocalIPPort, clientRemoteIP); err != nil {
		ns.logf("netstack: could not register TCP mapping %s: %v", backendLocalIPPort, err)
		return
	}
	defer ns.pm.UnregisterIPPortIdentity("tcp", backendLocalIPPort)

	// If we get here, either the getClient call below will succeed and
	// return something we can Close, or it will fail and will properly
	// respond to the client with a RST. Either way, the caller no longer
	// needs to clean up the client connection.
	handled = true

	// We dialed the connection; we can complete the client's TCP handshake.
	client := getClient()
	if client == nil {
		return
	}
	defer client.Close()

	// As of 2025-07-03, backend is always either a net.TCPConn
	// from stdDialer.DialContext (which has the requisite functions),
	// or nil from hangDialer in tests (in which case we would have
	// errored out by now), so this conversion should always succeed.
	backendTCPCloser, backendIsTCPCloser := backend.(tcpCloser)
	connClosed := make(chan error, 2)
	go func() {
		_, err := io.Copy(backend, client)
		if err != nil {
			err = fmt.Errorf("client -> backend: %w", err)
		}
		connClosed <- err
		err = nil
		if backendIsTCPCloser {
			err = backendTCPCloser.CloseWrite()
		}
		err = errors.Join(err, client.CloseRead())
		if err != nil {
			ns.logf("client -> backend close connection: %v", err)
		}
	}()
	go func() {
		_, err := io.Copy(client, backend)
		if err != nil {
			err = fmt.Errorf("backend -> client: %w", err)
		}
		connClosed <- err
		err = nil
		if backendIsTCPCloser {
			err = backendTCPCloser.CloseRead()
		}
		err = errors.Join(err, client.CloseWrite())
		if err != nil {
			ns.logf("backend -> client close connection: %v", err)
		}
	}()
	// Wait for both ends of the connection to close.
	for range 2 {
		err = <-connClosed
		if err != nil {
			ns.logf("proxy connection closed with error: %v", err)
		}
	}
	ns.logf("[v2] netstack: forwarder connection to %s closed", dialAddrStr)
	return
}

// ListenPacket listens for incoming packets for the given network and address.
// Address must be of the form "ip:port" or "[ip]:port".
//
// As of 2024-05-18, only udp4 and udp6 are supported.
func (ns *Impl) ListenPacket(network, address string) (net.PacketConn, error) {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("netstack: ParseAddrPort(%q): %v", address, err)
	}

	var networkProto tcpip.NetworkProtocolNumber
	switch network {
	case "udp":
		return nil, fmt.Errorf("netstack: udp not supported; use udp4 or udp6")
	case "udp4":
		networkProto = ipv4.ProtocolNumber
		if !ap.Addr().Is4() {
			return nil, fmt.Errorf("netstack: udp4 requires an IPv4 address")
		}
	case "udp6":
		networkProto = ipv6.ProtocolNumber
		if !ap.Addr().Is6() {
			return nil, fmt.Errorf("netstack: udp6 requires an IPv6 address")
		}
	default:
		return nil, fmt.Errorf("netstack: unsupported network %q", network)
	}
	var wq waiter.Queue
	ep, nserr := ns.ipstack.NewEndpoint(udp.ProtocolNumber, networkProto, &wq)
	if nserr != nil {
		return nil, fmt.Errorf("netstack: NewEndpoint: %v", nserr)
	}
	localAddress := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(ap.Addr().AsSlice()),
		Port: ap.Port(),
	}
	if err := ep.Bind(localAddress); err != nil {
		ep.Close()
		return nil, fmt.Errorf("netstack: Bind(%v): %v", localAddress, err)
	}
	return gonet.NewUDPConn(&wq, ep), nil
}

func (ns *Impl) acceptUDP(r *udp.ForwarderRequest) {
	sess := r.ID()
	if debugNetstack() {
		ns.logf("[v2] UDP ForwarderRequest: %v", stringifyTEI(sess))
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		ns.logf("acceptUDP: could not create endpoint: %v", err)
		return
	}
	dstAddr, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
	if !ok {
		ep.Close()
		return
	}
	srcAddr, ok := ipPortOfNetstackAddr(sess.RemoteAddress, sess.RemotePort)
	if !ok {
		ep.Close()
		return
	}

	// Handle magicDNS and loopback traffic (via UDP) here.
	if dst := dstAddr.Addr(); dst == serviceIP || dst == serviceIPv6 {
		switch {
		case dstAddr.Port() == 53:
			c := gonet.NewUDPConn(&wq, ep)
			go ns.handleMagicDNSUDP(srcAddr, c)
			return
		case ns.isLoopbackPort(dstAddr.Port()):
			if dst == serviceIPv6 {
				dstAddr = netip.AddrPortFrom(ipv6Loopback, dstAddr.Port())
			} else {
				dstAddr = netip.AddrPortFrom(ipv4Loopback, dstAddr.Port())
			}
		default:
			ep.Close()
			return // Only MagicDNS and loopback traffic runs on the service IPs for now.
		}
	}

	if get := ns.GetUDPHandlerForFlow; get != nil {
		h, intercept := get(srcAddr, dstAddr)
		if intercept {
			if h == nil {
				ep.Close()
				return
			}
			go h(gonet.NewUDPConn(&wq, ep))
			return
		}
	}

	c := gonet.NewUDPConn(&wq, ep)
	go ns.forwardUDP(c, srcAddr, dstAddr)
}

// Buffer pool for forwarding UDP packets. Implementations are advised not to
// exceed 512 bytes per DNS request due to fragmenting but in reality can and do
// send much larger packets, so use the maximum possible UDP packet size.
var udpBufPool = &sync.Pool{
	New: func() any {
		b := make([]byte, maxUDPPacketSize)
		return &b
	},
}

func (ns *Impl) handleMagicDNSUDP(srcAddr netip.AddrPort, c *gonet.UDPConn) {
	// Packets are being generated by the local host, so there should be
	// very, very little latency. 150ms was chosen as something of an upper
	// bound on resource usage, while hopefully still being long enough for
	// a heavily loaded system.
	const readDeadline = 150 * time.Millisecond

	defer c.Close()

	bufp := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufp)
	q := *bufp

	// libresolv from glibc is quite adamant that transmitting multiple DNS
	// requests down the same UDP socket is valid. To support this, we read
	// in a loop (with a tight deadline so we don't chew too many resources).
	//
	// See: https://github.com/bminor/glibc/blob/f7fbb99652eceb1b6b55e4be931649df5946497c/resolv/res_send.c#L995
	for {
		c.SetReadDeadline(time.Now().Add(readDeadline))
		n, _, err := c.ReadFrom(q)
		if err != nil {
			if oe, ok := err.(*net.OpError); !(ok && oe.Timeout()) {
				ns.logf("dns udp read: %v", err) // log non-timeout errors
			}
			return
		}
		resp, err := ns.dns.Query(context.Background(), q[:n], "udp", srcAddr)
		if err != nil {
			ns.logf("dns udp query: %v", err)
			return
		}
		c.Write(resp)
	}
}

// forwardUDP proxies between client (with addr clientAddr) and dstAddr.
//
// dstAddr may be either a local Tailscale IP, in which we case we proxy to
// 127.0.0.1, or any other IP (from an advertised subnet), in which case we
// proxy to it directly.
func (ns *Impl) forwardUDP(client *gonet.UDPConn, clientAddr, dstAddr netip.AddrPort) {
	port, srcPort := dstAddr.Port(), clientAddr.Port()
	if debugNetstack() {
		ns.logf("[v2] netstack: forwarding incoming UDP connection on port %v", port)
	}

	var backendListenAddr *net.UDPAddr
	var backendRemoteAddr *net.UDPAddr
	isLocal := ns.isLocalIP(dstAddr.Addr())
	isLoopback := dstAddr.Addr() == ipv4Loopback || dstAddr.Addr() == ipv6Loopback
	if isLocal {
		backendRemoteAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(srcPort)}
	} else if isLoopback {
		ip := net.IP(ipv4Loopback.AsSlice())
		if dstAddr.Addr() == ipv6Loopback {
			ip = ipv6Loopback.AsSlice()
		}
		backendRemoteAddr = &net.UDPAddr{IP: ip, Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: ip, Port: int(srcPort)}
	} else {
		if dstIP := dstAddr.Addr(); viaRange.Contains(dstIP) {
			dstAddr = netip.AddrPortFrom(tsaddr.UnmapVia(dstIP), dstAddr.Port())
		}
		backendRemoteAddr = net.UDPAddrFromAddrPort(dstAddr)
		if dstAddr.Addr().Is4() {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(srcPort)}
		} else {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("::"), Port: int(srcPort)}
		}
	}

	backendConn, err := net.ListenUDP("udp", backendListenAddr)
	if err != nil {
		ns.logf("netstack: could not bind local port %v: %v, trying again with random port", backendListenAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = net.ListenUDP("udp", backendListenAddr)
		if err != nil {
			ns.logf("netstack: could not create UDP socket, preventing forwarding to %v: %v", dstAddr, err)
			return
		}
	}
	backendLocalAddr := backendConn.LocalAddr().(*net.UDPAddr)

	backendLocalIPPort := netip.AddrPortFrom(backendListenAddr.AddrPort().Addr().Unmap().WithZone(backendLocalAddr.Zone), backendLocalAddr.AddrPort().Port())
	if !backendLocalIPPort.IsValid() {
		ns.logf("could not get backend local IP:port from %v:%v", backendLocalAddr.IP, backendLocalAddr.Port)
	}
	if isLocal {
		if err := ns.pm.RegisterIPPortIdentity("udp", backendLocalIPPort, clientAddr.Addr()); err != nil {
			ns.logf("netstack: could not register UDP mapping %s: %v", backendLocalIPPort, err)
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())

	idleTimeout := 2 * time.Minute
	if port == 53 {
		// Make DNS packet copies time out much sooner.
		//
		// TODO(bradfitz): make DNS queries over UDP forwarding even
		// cheaper by adding an additional idleTimeout post-DNS-reply.
		// For instance, after the DNS response goes back out, then only
		// wait a few seconds (or zero, really)
		idleTimeout = 30 * time.Second
	}
	timer := time.AfterFunc(idleTimeout, func() {
		if isLocal {
			ns.pm.UnregisterIPPortIdentity("udp", backendLocalIPPort)
		}
		ns.logf("netstack: UDP session between %s and %s timed out", backendListenAddr, backendRemoteAddr)
		cancel()
		client.Close()
		backendConn.Close()
	})
	extend := func() {
		timer.Reset(idleTimeout)
	}
	startPacketCopy(ctx, cancel, client, net.UDPAddrFromAddrPort(clientAddr), backendConn, ns.logf, extend)
	startPacketCopy(ctx, cancel, backendConn, backendRemoteAddr, client, ns.logf, extend)
	if isLocal {
		// Wait for the copies to be done before decrementing the
		// subnet address count to potentially remove the route.
		<-ctx.Done()
		ns.removeSubnetAddress(dstAddr.Addr())
	}
}

func startPacketCopy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, logf logger.Logf, extend func()) {
	if debugNetstack() {
		logf("[v2] netstack: startPacketCopy to %v (%T) from %T", dstAddr, dst, src)
	}
	go func() {
		defer cancel() // tear down the other direction's copy

		bufp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufp)
		pkt := *bufp

		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, srcAddr, err := src.ReadFrom(pkt)
				if err != nil {
					if ctx.Err() == nil {
						logf("read packet from %s failed: %v", srcAddr, err)
					}
					return
				}
				_, err = dst.WriteTo(pkt[:n], dstAddr)
				if err != nil {
					if ctx.Err() == nil {
						logf("write packet to %s failed: %v", dstAddr, err)
					}
					return
				}
				if debugNetstack() {
					logf("[v2] wrote UDP packet %s -> %s", srcAddr, dstAddr)
				}
				extend()
			}
		}
	}()
}

func stringifyTEI(tei stack.TransportEndpointID) string {
	localHostPort := net.JoinHostPort(tei.LocalAddress.String(), strconv.Itoa(int(tei.LocalPort)))
	remoteHostPort := net.JoinHostPort(tei.RemoteAddress.String(), strconv.Itoa(int(tei.RemotePort)))
	return fmt.Sprintf("%s -> %s", remoteHostPort, localHostPort)
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	if addr, ok := netip.AddrFromSlice(a.AsSlice()); ok {
		return netip.AddrPortFrom(addr, port), true
	}
	return netip.AddrPort{}, false
}

func readStatCounter(sc *tcpip.StatCounter) int64 {
	vv := sc.Value()
	if vv > math.MaxInt64 {
		return int64(math.MaxInt64)
	}
	return int64(vv)
}

// ExpVar returns an expvar variable suitable for registering with expvar.Publish.
func (ns *Impl) ExpVar() expvar.Var {
	m := new(metrics.Set)

	// Global metrics
	stats := ns.ipstack.Stats()
	m.Set("counter_dropped_packets", expvar.Func(func() any {
		return readStatCounter(stats.DroppedPackets)
	}))

	// IP statistics
	ipStats := ns.ipstack.Stats().IP
	ipMetrics := []struct {
		name  string
		field *tcpip.StatCounter
	}{
		{"packets_received", ipStats.PacketsReceived},
		{"valid_packets_received", ipStats.ValidPacketsReceived},
		{"disabled_packets_received", ipStats.DisabledPacketsReceived},
		{"invalid_destination_addresses_received", ipStats.InvalidDestinationAddressesReceived},
		{"invalid_source_addresses_received", ipStats.InvalidSourceAddressesReceived},
		{"packets_delivered", ipStats.PacketsDelivered},
		{"packets_sent", ipStats.PacketsSent},
		{"outgoing_packet_errors", ipStats.OutgoingPacketErrors},
		{"malformed_packets_received", ipStats.MalformedPacketsReceived},
		{"malformed_fragments_received", ipStats.MalformedFragmentsReceived},
		{"iptables_prerouting_dropped", ipStats.IPTablesPreroutingDropped},
		{"iptables_input_dropped", ipStats.IPTablesInputDropped},
		{"iptables_forward_dropped", ipStats.IPTablesForwardDropped},
		{"iptables_output_dropped", ipStats.IPTablesOutputDropped},
		{"iptables_postrouting_dropped", ipStats.IPTablesPostroutingDropped},
		{"option_timestamp_received", ipStats.OptionTimestampReceived},
		{"option_record_route_received", ipStats.OptionRecordRouteReceived},
		{"option_router_alert_received", ipStats.OptionRouterAlertReceived},
		{"option_unknown_received", ipStats.OptionUnknownReceived},
	}
	for _, metric := range ipMetrics {
		m.Set("counter_ip_"+metric.name, expvar.Func(func() any {
			return readStatCounter(metric.field)
		}))
	}

	// IP forwarding statistics
	fwdStats := ipStats.Forwarding
	fwdMetrics := []struct {
		name  string
		field *tcpip.StatCounter
	}{
		{"unrouteable", fwdStats.Unrouteable},
		{"exhausted_ttl", fwdStats.ExhaustedTTL},
		{"initializing_source", fwdStats.InitializingSource},
		{"link_local_source", fwdStats.LinkLocalSource},
		{"link_local_destination", fwdStats.LinkLocalDestination},
		{"packet_too_big", fwdStats.PacketTooBig},
		{"host_unreachable", fwdStats.HostUnreachable},
		{"extension_header_problem", fwdStats.ExtensionHeaderProblem},
		{"unexpected_multicast_input_interface", fwdStats.UnexpectedMulticastInputInterface},
		{"unknown_output_endpoint", fwdStats.UnknownOutputEndpoint},
		{"no_multicast_pending_queue_buffer_space", fwdStats.NoMulticastPendingQueueBufferSpace},
		{"outgoing_device_no_buffer_space", fwdStats.OutgoingDeviceNoBufferSpace},
		{"errors", fwdStats.Errors},
	}
	for _, metric := range fwdMetrics {
		m.Set("counter_ip_forward_"+metric.name, expvar.Func(func() any {
			return readStatCounter(metric.field)
		}))
	}

	// TCP metrics
	tcpStats := ns.ipstack.Stats().TCP
	tcpMetrics := []struct {
		name  string
		field *tcpip.StatCounter
	}{
		{"active_connection_openings", tcpStats.ActiveConnectionOpenings},
		{"passive_connection_openings", tcpStats.PassiveConnectionOpenings},
		{"established_resets", tcpStats.EstablishedResets},
		{"established_closed", tcpStats.EstablishedClosed},
		{"established_timeout", tcpStats.EstablishedTimedout},
		{"listen_overflow_syn_drop", tcpStats.ListenOverflowSynDrop},
		{"listen_overflow_ack_drop", tcpStats.ListenOverflowAckDrop},
		{"listen_overflow_syn_cookie_sent", tcpStats.ListenOverflowSynCookieSent},
		{"listen_overflow_syn_cookie_rcvd", tcpStats.ListenOverflowSynCookieRcvd},
		{"listen_overflow_invalid_syn_cookie_rcvd", tcpStats.ListenOverflowInvalidSynCookieRcvd},
		{"failed_connection_attempts", tcpStats.FailedConnectionAttempts},
		{"valid_segments_received", tcpStats.ValidSegmentsReceived},
		{"invalid_segments_received", tcpStats.InvalidSegmentsReceived},
		{"segments_sent", tcpStats.SegmentsSent},
		{"segment_send_errors", tcpStats.SegmentSendErrors},
		{"resets_sent", tcpStats.ResetsSent},
		{"resets_received", tcpStats.ResetsReceived},
		{"retransmits", tcpStats.Retransmits},
		{"fast_recovery", tcpStats.FastRecovery},
		{"sack_recovery", tcpStats.SACKRecovery},
		{"tlp_recovery", tcpStats.TLPRecovery},
		{"slow_start_retransmits", tcpStats.SlowStartRetransmits},
		{"fast_retransmit", tcpStats.FastRetransmit},
		{"timeouts", tcpStats.Timeouts},
		{"checksum_errors", tcpStats.ChecksumErrors},
		{"failed_port_reservations", tcpStats.FailedPortReservations},
		{"segments_acked_with_dsack", tcpStats.SegmentsAckedWithDSACK},
		{"spurious_recovery", tcpStats.SpuriousRecovery},
		{"spurious_rto_recovery", tcpStats.SpuriousRTORecovery},
		{"forward_max_in_flight_drop", tcpStats.ForwardMaxInFlightDrop},
	}
	for _, metric := range tcpMetrics {
		m.Set("counter_tcp_"+metric.name, expvar.Func(func() any {
			return readStatCounter(metric.field)
		}))
	}
	m.Set("gauge_tcp_current_established", expvar.Func(func() any {
		return readStatCounter(tcpStats.CurrentEstablished)
	}))
	m.Set("gauge_tcp_current_connected", expvar.Func(func() any {
		return readStatCounter(tcpStats.CurrentConnected)
	}))

	// UDP metrics
	udpStats := ns.ipstack.Stats().UDP
	udpMetrics := []struct {
		name  string
		field *tcpip.StatCounter
	}{
		{"packets_received", udpStats.PacketsReceived},
		{"unknown_port_errors", udpStats.UnknownPortErrors},
		{"receive_buffer_errors", udpStats.ReceiveBufferErrors},
		{"malformed_packets_received", udpStats.MalformedPacketsReceived},
		{"packets_sent", udpStats.PacketsSent},
		{"packet_send_errors", udpStats.PacketSendErrors},
		{"checksum_errors", udpStats.ChecksumErrors},
	}
	for _, metric := range udpMetrics {
		m.Set("counter_udp_"+metric.name, expvar.Func(func() any {
			return readStatCounter(metric.field)
		}))
	}

	// Export gauges that show the current TCP forwarding limits.
	m.Set("gauge_tcp_forward_in_flight_limit", expvar.Func(func() any {
		return maxInFlightConnectionAttempts()
	}))
	m.Set("gauge_tcp_forward_in_flight_per_client_limit", expvar.Func(func() any {
		return maxInFlightConnectionAttemptsPerClient()
	}))

	// This metric tracks the number of in-flight TCP forwarding
	// connections that are "in-flight"–i.e. waiting to complete.
	m.Set("gauge_tcp_forward_in_flight", expvar.Func(func() any {
		ns.mu.Lock()
		defer ns.mu.Unlock()

		var sum int64
		for _, n := range ns.connsInFlightByClient {
			sum += int64(n)
		}
		return sum
	}))

	m.Set("counter_tcp_forward_max_in_flight_per_client_drop", &ns.forwardInFlightPerClientDropped)

	// This metric tracks how many (if any) of the per-client limit on
	// in-flight TCP forwarding requests have been reached.
	m.Set("gauge_tcp_forward_in_flight_per_client_limit_reached", expvar.Func(func() any {
		ns.mu.Lock()
		defer ns.mu.Unlock()

		limit := maxInFlightConnectionAttemptsPerClient()

		var count int64
		for _, n := range ns.connsInFlightByClient {
			if n == limit {
				count++
			}
		}
		return count
	}))

	return m
}

// windowsPingOutputIsSuccess reports whether the ping.exe output b contains a
// success ping response for ip.
//
// See https://github.com/tailscale/tailscale/issues/13654
//
// TODO(bradfitz,nickkhyl): delete this and use the proper Windows APIs.
func windowsPingOutputIsSuccess(ip netip.Addr, b []byte) bool {
	// Look for a line that contains " <ip>: " and then three equal signs.
	// As a special case, the 2nd equal sign may be a '<' character
	// for sub-millisecond pings.
	// This heuristic seems to match the ping.exe output in any language.
	sub := fmt.Appendf(nil, " %s: ", ip)

	eqSigns := func(bb []byte) (n int) {
		for _, b := range bb {
			if b == '=' || (b == '<' && n == 1) {
				n++
			}
		}
		return
	}

	for len(b) > 0 {
		var line []byte
		line, b, _ = bytes.Cut(b, []byte("\n"))
		if _, rest, ok := bytes.Cut(line, sub); ok && eqSigns(rest) == 3 {
			return true
		}
	}
	return false
}
