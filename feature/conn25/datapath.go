// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"context"
	"errors"
	"net/netip"

	"tailscale.com/envknob"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/net/tstun"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

var (
	ErrUnmappedMagicIP         = errors.New("unmapped magic IP")
	ErrUnmappedSrcAndTransitIP = errors.New("unmapped src and transit IP")
)

// Conn25Datapath is the interface for the surface of [*Conn25] that the datapath
// handler needs. It provides methods for address mapping to help the datapath handler
// implement DNAT/SNAT, and flow lifecycle handlers so that *Conn25 can keep address
// assignments active for active flows.
//
// [*Conn25] is the only production implementation; the interface exists to let
// datapath tests substitute a lightweight fake.
type Conn25Datapath interface {
	// ClientTransitIPForMagicIP returns a Transit IP for the given magicIP on a client.
	// If the magicIP is within a configured Magic IP range for an app on the client,
	// but not mapped to an active Transit IP, implementations should return [ErrUnmappedMagicIP].
	// If magicIP is not within a configured Magic IP range, i.e. it is not actually a Magic IP,
	// implementations should return a nil error, and a zero-value [netip.Addr] to indicate
	// this potentially valid, non-app-connector traffic.
	ClientTransitIPForMagicIP(magicIP netip.Addr) (netip.Addr, error)

	// ConnectorRealIPForTransitIPConnection returns a real destination IP for the given
	// srcIP and transitIP on a connector. If the transitIP is within a configured Transit IP
	// range for an app on the connector, but not mapped to the client at srcIP, implementations
	// should return [ErrUnmappedSrcAndTransitIP]. If the transitIP is not within a configured
	// Transit IP range, i.e. it is not actually a Transit IP, implementations should return
	// a nil error, and a zero-value [netip.Addr] to indicate this is potentially valid,
	// non-app-connector traffic.
	ConnectorRealIPForTransitIPConnection(srcIP netip.Addr, transitIP netip.Addr) (netip.Addr, error)

	// ClientFlowCreated is called after a client-side flow for transitIP has
	// been installed in the client flow table.
	ClientFlowCreated(transitIP netip.Addr)
	// ClientFlowRemoved is called after such a flow is removed. For each
	// flow installed in the client flow table, ClientFlowCreated is called
	// before any ClientFlowRemoved that fires for it.
	ClientFlowRemoved(transitIP netip.Addr)
}

// datapathHandler handles packets from the datapath,
// performing appropriate NAT operations to support Connectors 2025.
// It maintains [FlowTable] caches for fast lookups of established flows.
//
// When hooked into the main datapath filter chain in [tstun], the datapathHandler
// will see every packet on the node, regardless of whether it is relevant to
// app connector operations. In the common case of non-connector traffic, it
// passes the packet through unmodified.
//
// It classifies each packet based on the presence of special Magic IPs or
// Transit IPs, and determines whether the packet is flowing through a "client"
// (the node with the application that starts the connection), or a "connector"
// (the node that connects to the internet-hosted destination). On the client,
// outbound connections are DNATed from Magic IP to Transit IP, and return
// traffic is SNATed from Transit IP to Magic IP. On the connector, outbound
// connections are DNATed from Transit IP to real IP, and return traffic is
// SNATed from real IP to Transit IP.
//
// There are two exposed methods, one for handling packets from the tun device,
// and one for handling packets from WireGuard, but through the use of flow tables,
// we can handle four cases: client outbound, client return, connector outbound,
// connector return. The first packet goes through [Conn25Datapath], which is where
// Connectors 2025 authoritative state is stored. For valid packets relevant to connectors,
// a bidirectional flow entry is installed, so that subsequent packets (and all return traffic)
// hit that cache. Only outbound (towards internet) packets create new flows; return (from internet)
// packets either match a cached entry or pass through.
//
// We check the cache before [Conn25Datapath] both for performance, and so that existing flows
// stay alive even if address mappings change mid-flow.
type datapathHandler struct {
	conn25 Conn25Datapath

	// Flow caches. One for the client, and one for the connector.
	clientFlowTable    *FlowTable
	connectorFlowTable *FlowTable

	logf         logger.Logf
	debugLogging bool
}

const (
	maxClientFlows    = 10_000
	maxConnectorFlows = 100_000
)

func newDatapathHandler(conn25 Conn25Datapath, logf logger.Logf) *datapathHandler {
	return &datapathHandler{
		conn25:             conn25,
		clientFlowTable:    NewFlowTable(maxClientFlows),
		connectorFlowTable: NewFlowTable(maxConnectorFlows),
		logf:               logf,
		debugLogging:       envknob.Bool("TS_CONN25_DATAPATH_DEBUG"),
	}
}

// StartFlowExpirySweepers starts the sweepers that remove expired flows
// for both the client and connector flow tables. Each sweeper runs in
// its own new goroutine.
func (dh *datapathHandler) StartFlowExpirySweepers(ctx context.Context) {
	go dh.clientFlowTable.StartExpiredSweeper(ctx)
	go dh.connectorFlowTable.StartExpiredSweeper(ctx)
}

func isSupportedProtocol(proto ipproto.Proto) bool {
	return proto == ipproto.TCP || proto == ipproto.UDP || proto == ipproto.ICMPv4 || proto == ipproto.ICMPv6
}

// HandlePacketFromWireGuard inspects packets coming from WireGuard, and performs
// appropriate DNAT or SNAT actions for Connectors 2025. Returning [filter.Accept] signals
// that the packet should pass through subsequent stages of the datapath pipeline.
// Returning [filter.Drop] signals the packet should be dropped. This method handles all
// packets coming from WireGuard, on both connectors, and clients of connectors.
func (dh *datapathHandler) HandlePacketFromWireGuard(p *packet.Parsed, tun *tstun.Wrapper) filter.Response {
	if !isSupportedProtocol(p.IPProto) {
		return filter.Accept
	}

	// Check if this is an existing (return) flow on a client.
	// If found, perform the action for the existing client flow and return.
	action, ok := dh.clientFlowTable.LookupFromWireGuard(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		action(p)
		return filter.Accept
	}

	// Check if this is an existing connector outbound flow.
	// If found, perform the action for the existing connector outbound flow and return.
	action, ok = dh.connectorFlowTable.LookupFromWireGuard(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		action(p)
		return filter.Accept
	}

	// The flow was not found in either flow table. Since the packet came in
	// from WireGuard, it can only be a new flow on the connector,
	// other (non-app-connector) traffic, or broken app-connector traffic
	// that needs to be re-established by a new outbound packet.
	transitIP := p.Dst.Addr()
	realIP, err := dh.conn25.ConnectorRealIPForTransitIPConnection(p.Src.Addr(), transitIP)
	if err != nil {
		if errors.Is(err, ErrUnmappedSrcAndTransitIP) {
			rj := packet.TailscaleRejectedHeader{
				IPSrc:  p.Dst.Addr(),
				IPDst:  p.Src.Addr(),
				Src:    p.Src,
				Dst:    p.Dst,
				Proto:  p.IPProto,
				Reason: packet.RejectedDueToUnknownAppConnectorTransitIP,
			}
			if err := tun.InjectOutbound(packet.Generate(rj, nil)); err != nil {
				dh.debugLogf("error sending TSMP flow rejection packet: %v", err)
			}
			return filter.Drop
		}
		dh.debugLogf("error mapping src and transit IP, passing packet unmodified: %v", err)
		return filter.Accept
	}

	// If this is normal non-app-connector traffic, forward it along unmodified.
	if !realIP.IsValid() {
		return filter.Accept
	}

	// This is a new outbound flow on a connector. Install a DNAT TransitIP-to-RealIP action
	// for the outgoing direction, and an SNAT RealIP-to-TransitIP action for the
	// return direction.
	outgoing := TupleAndAction{
		Tuple:  flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst),
		Action: dh.dnatAction(realIP),
	}
	incoming := TupleAndAction{
		Tuple:  flowtrack.MakeTuple(p.IPProto, netip.AddrPortFrom(realIP, p.Dst.Port()), p.Src),
		Action: dh.snatAction(transitIP),
	}
	dh.connectorFlowTable.NewFlow(FlowData{
		FromTun: incoming,
		FromWG:  outgoing,
	})
	outgoing.Action(p)
	return filter.Accept
}

// HandlePacketFromTunDevice inspects packets coming from the tun device, and performs
// appropriate DNAT or SNAT actions for Connectors 2025. Returning [filter.Accept] signals
// that the packet should pass through subsequent stages of the datapath pipeline.
// Returning [filter.Drop] signals the packet should be dropped. This method handles all
// packets coming from the tun device, on both connectors, and clients of connectors.
func (dh *datapathHandler) HandlePacketFromTunDevice(p *packet.Parsed, tun *tstun.Wrapper) filter.Response {
	if !isSupportedProtocol(p.IPProto) {
		return filter.Accept
	}

	// Check if this is an existing client outbound flow.
	// If found, perform the action for the existing client flow and return.
	action, ok := dh.clientFlowTable.LookupFromTunDevice(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		action(p)
		return filter.Accept
	}

	// Check if this is an existing connector return flow.
	// If found, perform the action for the existing connector return flow and return.
	action, ok = dh.connectorFlowTable.LookupFromTunDevice(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		action(p)
		return filter.Accept
	}

	// The flow was not found in either flow table. Since the packet came in on the
	// tun device, it can only be a new client flow, other (non-app-connector) traffic,
	// or broken return app-connector traffic on a connector, which needs to be re-established
	// with a new outbound packet.
	magicIP := p.Dst.Addr()
	transitIP, err := dh.conn25.ClientTransitIPForMagicIP(magicIP)
	if err != nil {
		if errors.Is(err, ErrUnmappedMagicIP) {
			// Couldn't find a mapping. Tell the local application the host is
			// unreachable so it can recover quickly instead of blackholing.
			dh.sendICMPHostUnreachable(p, tun)
			return filter.Drop
		}
		dh.debugLogf("error mapping magic IP, passing packet unmodified: %v", err)
		return filter.Accept
	}

	// If this is normal non-app-connector traffic, forward it along unmodified.
	if !transitIP.IsValid() {
		return filter.Accept
	}

	// This is a new outbound client flow. Install a DNAT MagicIP-to-TransitIP action
	// for the outgoing direction, and an SNAT TransitIP-to-MagicIP action for the
	// return direction.
	outgoing := TupleAndAction{
		Tuple:  flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst),
		Action: dh.dnatAction(transitIP),
	}
	incoming := TupleAndAction{
		Tuple:  flowtrack.MakeTuple(p.IPProto, netip.AddrPortFrom(transitIP, p.Dst.Port()), p.Src),
		Action: dh.snatAction(magicIP),
	}

	// Notify Conn25 that a flow for transitIP is being established before
	// installing it in the flow table. This guarantees that ClientFlowCreated
	// for this flow precedes any ClientFlowRemoved that fires for it.
	dh.conn25.ClientFlowCreated(transitIP)

	dh.clientFlowTable.NewFlow(FlowData{
		FromTun: outgoing,
		FromWG:  incoming,
		OnRemove: func() {
			dh.conn25.ClientFlowRemoved(transitIP)
		},
	})
	outgoing.Action(p)
	return filter.Accept
}

// sendICMPHostUnreachable injects an ICMP "host unreachable" error (or its IPv6
// equivalent, "address unreachable") back to the local host in response to the
// tun-device packet p. The error is delivered inbound so the local
// application that sent p sees it, giving it the chance to recover.
func (dh *datapathHandler) sendICMPHostUnreachable(p *packet.Parsed, tun *tstun.Wrapper) {
	// The error appears to come from the unreachable Magic IP, addressed back to
	// the sender, and embeds data from the invoking packet.
	errPkt := packet.GenerateICMPHostUnreachable(p.Dst.Addr(), p.Src.Addr(), p)
	if errPkt == nil {
		return
	}
	if err := tun.InjectInboundCopy(errPkt); err != nil {
		dh.debugLogf("error injecting ICMP host unreachable packet: %v", err)
	}
}

func (dh *datapathHandler) dnatAction(to netip.Addr) PacketAction {
	return PacketAction(func(p *packet.Parsed) { checksum.UpdateDstAddr(p, to) })
}

func (dh *datapathHandler) snatAction(to netip.Addr) PacketAction {
	return PacketAction(func(p *packet.Parsed) { checksum.UpdateSrcAddr(p, to) })
}

func (dh *datapathHandler) debugLogf(msg string, args ...any) {
	if dh.debugLogging {
		dh.logf(msg, args...)
	}
}
