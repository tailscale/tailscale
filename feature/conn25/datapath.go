// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"errors"
	"net/netip"

	"tailscale.com/envknob"
	"tailscale.com/net/flowtrack"
	"tailscale.com/net/packet"
	"tailscale.com/net/packet/checksum"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

var (
	ErrUnmappedMagicIP         = errors.New("unmapped magic IP")
	ErrUnmappedSrcAndTransitIP = errors.New("unmapped src and transit IP")
)

// IPMapper provides methods for mapping special app connector IPs to each other
// in aid of performing DNAT and SNAT on app connector packets.
type IPMapper interface {
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
// connector return. The first packet goes through IPMapper, which is where Connectors
// 2025 authoritative state is stored. For valid packets relevant to connectors,
// a bidirectional flow entry is installed, so that subsequent packets (and all return traffic)
// hit that cache. Only outbound (towards internet) packets create new flows; return (from internet)
// packets either match a cached entry or pass through.
//
// We check the cache before IPMapper both for performance, and so that existing flows stay alive
// even if address mappings change mid-flow.
type datapathHandler struct {
	ipMapper IPMapper

	// Flow caches. One for the client, and one for the connector.
	clientFlowTable    *FlowTable
	connectorFlowTable *FlowTable

	logf         logger.Logf
	debugLogging bool
}

func newDatapathHandler(ipMapper IPMapper, logf logger.Logf) *datapathHandler {
	return &datapathHandler{
		ipMapper: ipMapper,

		// TODO(mzb): Figure out sensible default max size for flow tables.
		// Don't do any LRU eviction until we figure out deletion and expiration.
		clientFlowTable:    NewFlowTable(0),
		connectorFlowTable: NewFlowTable(0),
		logf:               logf,
		debugLogging:       envknob.Bool("TS_CONN25_DATAPATH_DEBUG"),
	}
}

// HandlePacketFromWireGuard inspects packets coming from WireGuard, and performs
// appropriate DNAT or SNAT actions for Connectors 2025. Returning [filter.Accept] signals
// that the packet should pass through subsequent stages of the datapath pipeline.
// Returning [filter.Drop] signals the packet should be dropped. This method handles all
// packets coming from WireGuard, on both connectors, and clients of connectors.
func (dh *datapathHandler) HandlePacketFromWireGuard(p *packet.Parsed) filter.Response {
	// TODO(tailscale/corp#38764): Support other protocols, like ICMP for error messages.
	if p.IPProto != ipproto.TCP && p.IPProto != ipproto.UDP {
		return filter.Accept
	}

	// Check if this is an existing (return) flow on a client.
	// If found, perform the action for the existing client flow and return.
	existing, ok := dh.clientFlowTable.LookupFromWireGuard(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		existing.Action(p)
		return filter.Accept
	}

	// Check if this is an existing connector outbound flow.
	// If found, perform the action for the existing connector outbound flow and return.
	existing, ok = dh.connectorFlowTable.LookupFromWireGuard(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		existing.Action(p)
		return filter.Accept
	}

	// The flow was not found in either flow table. Since the packet came in
	// from WireGuard, it can only be a new flow on the connector,
	// other (non-app-connector) traffic, or broken app-connector traffic
	// that needs to be re-established by a new outbound packet.
	transitIP := p.Dst.Addr()
	realIP, err := dh.ipMapper.ConnectorRealIPForTransitIPConnection(p.Src.Addr(), transitIP)
	if err != nil {
		if errors.Is(err, ErrUnmappedSrcAndTransitIP) {
			// TODO(tailscale/corp#34256): This path should deliver an ICMP error to the client.
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
	outgoing := FlowData{
		Tuple:  flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst),
		Action: dh.dnatAction(realIP),
	}
	incoming := FlowData{
		Tuple:  flowtrack.MakeTuple(p.IPProto, netip.AddrPortFrom(realIP, p.Dst.Port()), p.Src),
		Action: dh.snatAction(transitIP),
	}
	if err := dh.connectorFlowTable.NewFlowFromWireGuard(outgoing, incoming); err != nil {
		dh.debugLogf("error installing flow, passing packet unmodified: %v", err)
		return filter.Accept
	}
	outgoing.Action(p)
	return filter.Accept
}

// HandlePacketFromTunDevice inspects packets coming from the tun device, and performs
// appropriate DNAT or SNAT actions for Connectors 2025. Returning [filter.Accept] signals
// that the packet should pass through subsequent stages of the datapath pipeline.
// Returning [filter.Drop] signals the packet should be dropped. This method handles all
// packets coming from the tun device, on both connectors, and clients of connectors.
func (dh *datapathHandler) HandlePacketFromTunDevice(p *packet.Parsed) filter.Response {
	// TODO(tailscale/corp#38764): Support other protocols, like ICMP for error messages.
	if p.IPProto != ipproto.TCP && p.IPProto != ipproto.UDP {
		return filter.Accept
	}

	// Check if this is an existing client outbound flow.
	// If found, perform the action for the existing client flow and return.
	existing, ok := dh.clientFlowTable.LookupFromTunDevice(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		existing.Action(p)
		return filter.Accept
	}

	// Check if this is an existing connector return flow.
	// If found, perform the action for the existing connector return flow and return.
	existing, ok = dh.connectorFlowTable.LookupFromTunDevice(flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst))
	if ok {
		existing.Action(p)
		return filter.Accept
	}

	// The flow was not found in either flow table. Since the packet came in on the
	// tun device, it can only be a new client flow, other (non-app-connector) traffic,
	// or broken return app-connector traffic on a connector, which needs to be re-established
	// with a new outbound packet.
	magicIP := p.Dst.Addr()
	transitIP, err := dh.ipMapper.ClientTransitIPForMagicIP(magicIP)
	if err != nil {
		if errors.Is(err, ErrUnmappedMagicIP) {
			// TODO(tailscale/corp#34257): This path should deliver an ICMP error to the client.
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
	outgoing := FlowData{
		Tuple:  flowtrack.MakeTuple(p.IPProto, p.Src, p.Dst),
		Action: dh.dnatAction(transitIP),
	}
	incoming := FlowData{
		Tuple:  flowtrack.MakeTuple(p.IPProto, netip.AddrPortFrom(transitIP, p.Dst.Port()), p.Src),
		Action: dh.snatAction(magicIP),
	}
	if err := dh.clientFlowTable.NewFlowFromTunDevice(outgoing, incoming); err != nil {
		dh.debugLogf("error installing flow from tun device, passing packet unmodified: %v", err)
		return filter.Accept
	}
	outgoing.Action(p)
	return filter.Accept
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
