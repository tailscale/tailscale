// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stack

import (
	"fmt"
	"math"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// AcceptTarget accepts packets.
type AcceptTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*AcceptTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	return RuleAccept, 0
}

// DropTarget drops packets.
type DropTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*DropTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	return RuleDrop, 0
}

// RejectIPv4WithHandler handles rejecting a packet.
type RejectIPv4WithHandler interface {
	// SendRejectionError sends an error packet in response to the packet.
	SendRejectionError(pkt *PacketBuffer, rejectWith RejectIPv4WithICMPType, inputHook bool) tcpip.Error
}

// RejectIPv4WithICMPType indicates the type of ICMP error that should be sent.
type RejectIPv4WithICMPType int

// The types of errors that may be returned when rejecting IPv4 packets.
const (
	_ RejectIPv4WithICMPType = iota
	RejectIPv4WithICMPNetUnreachable
	RejectIPv4WithICMPHostUnreachable
	RejectIPv4WithICMPPortUnreachable
	RejectIPv4WithICMPNetProhibited
	RejectIPv4WithICMPHostProhibited
	RejectIPv4WithICMPAdminProhibited
)

// RejectIPv4Target drops packets and sends back an error packet in response to the
// matched packet.
type RejectIPv4Target struct {
	Handler    RejectIPv4WithHandler
	RejectWith RejectIPv4WithICMPType
}

// Action implements Target.Action.
func (rt *RejectIPv4Target) Action(pkt *PacketBuffer, hook Hook, _ *Route, _ AddressableEndpoint) (RuleVerdict, int) {
	switch hook {
	case Input, Forward, Output:
		// There is nothing reasonable for us to do in response to an error here;
		// we already drop the packet.
		_ = rt.Handler.SendRejectionError(pkt, rt.RejectWith, hook == Input)
		return RuleDrop, 0
	case Prerouting, Postrouting:
		panic(fmt.Sprintf("%s hook not supported for REDIRECT", hook))
	default:
		panic(fmt.Sprintf("unhandled hook = %s", hook))
	}
}

// RejectIPv6WithHandler handles rejecting a packet.
type RejectIPv6WithHandler interface {
	// SendRejectionError sends an error packet in response to the packet.
	SendRejectionError(pkt *PacketBuffer, rejectWith RejectIPv6WithICMPType, forwardingHook bool) tcpip.Error
}

// RejectIPv6WithICMPType indicates the type of ICMP error that should be sent.
type RejectIPv6WithICMPType int

// The types of errors that may be returned when rejecting IPv6 packets.
const (
	_ RejectIPv6WithICMPType = iota
	RejectIPv6WithICMPNoRoute
	RejectIPv6WithICMPAddrUnreachable
	RejectIPv6WithICMPPortUnreachable
	RejectIPv6WithICMPAdminProhibited
)

// RejectIPv6Target drops packets and sends back an error packet in response to the
// matched packet.
type RejectIPv6Target struct {
	Handler    RejectIPv6WithHandler
	RejectWith RejectIPv6WithICMPType
}

// Action implements Target.Action.
func (rt *RejectIPv6Target) Action(pkt *PacketBuffer, hook Hook, _ *Route, _ AddressableEndpoint) (RuleVerdict, int) {
	switch hook {
	case Input, Forward, Output:
		// There is nothing reasonable for us to do in response to an error here;
		// we already drop the packet.
		_ = rt.Handler.SendRejectionError(pkt, rt.RejectWith, hook == Input)
		return RuleDrop, 0
	case Prerouting, Postrouting:
		panic(fmt.Sprintf("%s hook not supported for REDIRECT", hook))
	default:
		panic(fmt.Sprintf("unhandled hook = %s", hook))
	}
}

// ErrorTarget logs an error and drops the packet. It represents a target that
// should be unreachable.
type ErrorTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*ErrorTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	log.Debugf("ErrorTarget triggered.")
	return RuleDrop, 0
}

// UserChainTarget marks a rule as the beginning of a user chain.
type UserChainTarget struct {
	// Name is the chain name.
	Name string

	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*UserChainTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	panic("UserChainTarget should never be called.")
}

// ReturnTarget returns from the current chain. If the chain is a built-in, the
// hook's underflow should be called.
type ReturnTarget struct {
	// NetworkProtocol is the network protocol the target is used with.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (*ReturnTarget) Action(*PacketBuffer, Hook, *Route, AddressableEndpoint) (RuleVerdict, int) {
	return RuleReturn, 0
}

// DNATTarget modifies the destination port/IP of packets.
type DNATTarget struct {
	// The new destination address for packets.
	//
	// Immutable.
	Addr tcpip.Address

	// The new destination port for packets.
	//
	// Immutable.
	Port uint16

	// NetworkProtocol is the network protocol the target is used with.
	//
	// Immutable.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (rt *DNATTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint) (RuleVerdict, int) {
	// Sanity check.
	if rt.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"DNATTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			rt.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	switch hook {
	case Prerouting, Output:
	case Input, Forward, Postrouting:
		panic(fmt.Sprintf("%s not supported for DNAT", hook))
	default:
		panic(fmt.Sprintf("%s unrecognized", hook))
	}

	return dnatAction(pkt, hook, r, rt.Port, rt.Addr)

}

// RedirectTarget redirects the packet to this machine by modifying the
// destination port/IP. Outgoing packets are redirected to the loopback device,
// and incoming packets are redirected to the incoming interface (rather than
// forwarded).
type RedirectTarget struct {
	// Port indicates port used to redirect. It is immutable.
	Port uint16

	// NetworkProtocol is the network protocol the target is used with. It
	// is immutable.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (rt *RedirectTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint) (RuleVerdict, int) {
	// Sanity check.
	if rt.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"RedirectTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			rt.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	// Change the address to loopback (127.0.0.1 or ::1) in Output and to
	// the primary address of the incoming interface in Prerouting.
	var address tcpip.Address
	switch hook {
	case Output:
		if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
			address = tcpip.Address([]byte{127, 0, 0, 1})
		} else {
			address = header.IPv6Loopback
		}
	case Prerouting:
		// addressEP is expected to be set for the prerouting hook.
		address = addressEP.MainAddress().Address
	default:
		panic("redirect target is supported only on output and prerouting hooks")
	}

	return dnatAction(pkt, hook, r, rt.Port, address)
}

// SNATTarget modifies the source port/IP in the outgoing packets.
type SNATTarget struct {
	Addr tcpip.Address
	Port uint16

	// NetworkProtocol is the network protocol the target is used with. It
	// is immutable.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func dnatAction(pkt *PacketBuffer, hook Hook, r *Route, port uint16, address tcpip.Address) (RuleVerdict, int) {
	return natAction(pkt, hook, r, portOrIdentRange{start: port, size: 1}, address, true /* dnat */)
}

func targetPortRangeForTCPAndUDP(originalSrcPort uint16) portOrIdentRange {
	// As per iptables(8),
	//
	//   If no port range is specified, then source ports below 512 will be
	//   mapped to other ports below 512: those between 512 and 1023 inclusive
	//   will be mapped to ports below 1024, and other ports will be mapped to
	//   1024 or above.
	switch {
	case originalSrcPort < 512:
		return portOrIdentRange{start: 1, size: 511}
	case originalSrcPort < 1024:
		return portOrIdentRange{start: 1, size: 1023}
	default:
		return portOrIdentRange{start: 1024, size: math.MaxUint16 - 1023}
	}
}

func snatAction(pkt *PacketBuffer, hook Hook, r *Route, port uint16, address tcpip.Address) (RuleVerdict, int) {
	portsOrIdents := portOrIdentRange{start: port, size: 1}

	switch pkt.TransportProtocolNumber {
	case header.UDPProtocolNumber:
		if port == 0 {
			portsOrIdents = targetPortRangeForTCPAndUDP(header.UDP(pkt.TransportHeader().View()).SourcePort())
		}
	case header.TCPProtocolNumber:
		if port == 0 {
			portsOrIdents = targetPortRangeForTCPAndUDP(header.TCP(pkt.TransportHeader().View()).SourcePort())
		}
	case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
		// Allow NAT-ing to any 16-bit value for ICMP's Ident field to match Linux
		// behaviour.
		//
		// https://github.com/torvalds/linux/blob/58e1100fdc5990b0cc0d4beaf2562a92e621ac7d/net/netfilter/nf_nat_core.c#L391
		portsOrIdents = portOrIdentRange{start: 0, size: math.MaxUint16 + 1}
	}

	return natAction(pkt, hook, r, portsOrIdents, address, false /* dnat */)
}

func natAction(pkt *PacketBuffer, hook Hook, r *Route, portsOrIdents portOrIdentRange, address tcpip.Address, dnat bool) (RuleVerdict, int) {
	// Drop the packet if network and transport header are not set.
	if pkt.NetworkHeader().View().IsEmpty() || pkt.TransportHeader().View().IsEmpty() {
		return RuleDrop, 0
	}

	if t := pkt.tuple; t != nil {
		t.conn.performNAT(pkt, hook, r, portsOrIdents, address, dnat)
		return RuleAccept, 0
	}

	return RuleDrop, 0
}

// Action implements Target.Action.
func (st *SNATTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, _ AddressableEndpoint) (RuleVerdict, int) {
	// Sanity check.
	if st.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"SNATTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			st.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	switch hook {
	case Postrouting, Input:
	case Prerouting, Output, Forward:
		panic(fmt.Sprintf("%s not supported", hook))
	default:
		panic(fmt.Sprintf("%s unrecognized", hook))
	}

	return snatAction(pkt, hook, r, st.Port, st.Addr)
}

// MasqueradeTarget modifies the source port/IP in the outgoing packets.
type MasqueradeTarget struct {
	// NetworkProtocol is the network protocol the target is used with. It
	// is immutable.
	NetworkProtocol tcpip.NetworkProtocolNumber
}

// Action implements Target.Action.
func (mt *MasqueradeTarget) Action(pkt *PacketBuffer, hook Hook, r *Route, addressEP AddressableEndpoint) (RuleVerdict, int) {
	// Sanity check.
	if mt.NetworkProtocol != pkt.NetworkProtocolNumber {
		panic(fmt.Sprintf(
			"MasqueradeTarget.Action with NetworkProtocol %d called on packet with NetworkProtocolNumber %d",
			mt.NetworkProtocol, pkt.NetworkProtocolNumber))
	}

	switch hook {
	case Postrouting:
	case Prerouting, Input, Forward, Output:
		panic(fmt.Sprintf("masquerade target is supported only on postrouting hook; hook = %d", hook))
	default:
		panic(fmt.Sprintf("%s unrecognized", hook))
	}

	// addressEP is expected to be set for the postrouting hook.
	ep := addressEP.AcquireOutgoingPrimaryAddress(pkt.Network().DestinationAddress(), false /* allowExpired */)
	if ep == nil {
		// No address exists that we can use as a source address.
		return RuleDrop, 0
	}

	address := ep.AddressWithPrefix().Address
	ep.DecRef()
	return snatAction(pkt, hook, r, 0 /* port */, address)
}

func rewritePacket(n header.Network, t header.Transport, updateSRCFields, fullChecksum, updatePseudoHeader bool, newPortOrIdent uint16, newAddr tcpip.Address) {
	switch t := t.(type) {
	case header.ChecksummableTransport:
		if updateSRCFields {
			if fullChecksum {
				t.SetSourcePortWithChecksumUpdate(newPortOrIdent)
			} else {
				t.SetSourcePort(newPortOrIdent)
			}
		} else {
			if fullChecksum {
				t.SetDestinationPortWithChecksumUpdate(newPortOrIdent)
			} else {
				t.SetDestinationPort(newPortOrIdent)
			}
		}

		if updatePseudoHeader {
			var oldAddr tcpip.Address
			if updateSRCFields {
				oldAddr = n.SourceAddress()
			} else {
				oldAddr = n.DestinationAddress()
			}

			t.UpdateChecksumPseudoHeaderAddress(oldAddr, newAddr, fullChecksum)
		}
	case header.ICMPv4:
		switch icmpType := t.Type(); icmpType {
		case header.ICMPv4Echo:
			if updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		case header.ICMPv4EchoReply:
			if !updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		default:
			panic(fmt.Sprintf("unexpected ICMPv4 type = %d", icmpType))
		}
	case header.ICMPv6:
		switch icmpType := t.Type(); icmpType {
		case header.ICMPv6EchoRequest:
			if updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		case header.ICMPv6EchoReply:
			if !updateSRCFields {
				t.SetIdentWithChecksumUpdate(newPortOrIdent)
			}
		default:
			panic(fmt.Sprintf("unexpected ICMPv4 type = %d", icmpType))
		}

		var oldAddr tcpip.Address
		if updateSRCFields {
			oldAddr = n.SourceAddress()
		} else {
			oldAddr = n.DestinationAddress()
		}

		t.UpdateChecksumPseudoHeaderAddress(oldAddr, newAddr)
	default:
		panic(fmt.Sprintf("unhandled transport = %#v", t))
	}

	if checksummableNetHeader, ok := n.(header.ChecksummableNetwork); ok {
		if updateSRCFields {
			checksummableNetHeader.SetSourceAddressWithChecksumUpdate(newAddr)
		} else {
			checksummableNetHeader.SetDestinationAddressWithChecksumUpdate(newAddr)
		}
	} else if updateSRCFields {
		n.SetSourceAddress(newAddr)
	} else {
		n.SetDestinationAddress(newAddr)
	}
}
