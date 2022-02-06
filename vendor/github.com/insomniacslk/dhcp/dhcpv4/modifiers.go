package dhcpv4

import (
	"net"
	"time"

	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

// WithTransactionID sets the Transaction ID for the DHCPv4 packet
func WithTransactionID(xid TransactionID) Modifier {
	return func(d *DHCPv4) {
		d.TransactionID = xid
	}
}

// WithClientIP sets the Client IP for a DHCPv4 packet.
func WithClientIP(ip net.IP) Modifier {
	return func(d *DHCPv4) {
		d.ClientIPAddr = ip
	}
}

// WithYourIP sets the Your IP for a DHCPv4 packet.
func WithYourIP(ip net.IP) Modifier {
	return func(d *DHCPv4) {
		d.YourIPAddr = ip
	}
}

// WithServerIP sets the Server IP for a DHCPv4 packet.
func WithServerIP(ip net.IP) Modifier {
	return func(d *DHCPv4) {
		d.ServerIPAddr = ip
	}
}

// WithGatewayIP sets the Gateway IP for the DHCPv4 packet.
func WithGatewayIP(ip net.IP) Modifier {
	return func(d *DHCPv4) {
		d.GatewayIPAddr = ip
	}
}

// WithOptionCopied copies the value of option opt from request.
func WithOptionCopied(request *DHCPv4, opt OptionCode) Modifier {
	return func(d *DHCPv4) {
		if val := request.Options.Get(opt); val != nil {
			d.UpdateOption(OptGeneric(opt, val))
		}
	}
}

// WithReply fills in opcode, hwtype, xid, clienthwaddr, and flags from the given packet.
func WithReply(request *DHCPv4) Modifier {
	return func(d *DHCPv4) {
		if request.OpCode == OpcodeBootRequest {
			d.OpCode = OpcodeBootReply
		} else {
			d.OpCode = OpcodeBootRequest
		}
		d.HWType = request.HWType
		d.TransactionID = request.TransactionID
		d.ClientHWAddr = request.ClientHWAddr
		d.Flags = request.Flags
	}
}

// WithHWType sets the Hardware Type for a DHCPv4 packet.
func WithHWType(hwt iana.HWType) Modifier {
	return func(d *DHCPv4) {
		d.HWType = hwt
	}
}

// WithBroadcast sets the packet to be broadcast or unicast
func WithBroadcast(broadcast bool) Modifier {
	return func(d *DHCPv4) {
		if broadcast {
			d.SetBroadcast()
		} else {
			d.SetUnicast()
		}
	}
}

// WithHwAddr sets the hardware address for a packet
func WithHwAddr(hwaddr net.HardwareAddr) Modifier {
	return func(d *DHCPv4) {
		d.ClientHWAddr = hwaddr
	}
}

// WithOption appends a DHCPv4 option provided by the user
func WithOption(opt Option) Modifier {
	return func(d *DHCPv4) {
		d.UpdateOption(opt)
	}
}

// WithUserClass adds a user class option to the packet.
// The rfc parameter allows you to specify if the userclass should be
// rfc compliant or not. More details in issue #113
func WithUserClass(uc string, rfc bool) Modifier {
	// TODO let the user specify multiple user classes
	return func(d *DHCPv4) {
		if rfc {
			d.UpdateOption(OptRFC3004UserClass([]string{uc}))
		} else {
			d.UpdateOption(OptUserClass(uc))
		}
	}
}

// WithNetboot adds bootfile URL and bootfile param options to a DHCPv4 packet.
func WithNetboot(d *DHCPv4) {
	WithRequestedOptions(OptionTFTPServerName, OptionBootfileName)(d)
}

// WithMessageType adds the DHCPv4 message type m to a packet.
func WithMessageType(m MessageType) Modifier {
	return WithOption(OptMessageType(m))
}

// WithRequestedOptions adds requested options to the packet.
func WithRequestedOptions(optionCodes ...OptionCode) Modifier {
	return func(d *DHCPv4) {
		cl := d.ParameterRequestList()
		cl.Add(optionCodes...)
		d.UpdateOption(OptParameterRequestList(cl...))
	}
}

// WithRelay adds parameters required for DHCPv4 to be relayed by the relay
// server with given ip
func WithRelay(ip net.IP) Modifier {
	return func(d *DHCPv4) {
		d.SetUnicast()
		d.GatewayIPAddr = ip
		d.HopCount++
	}
}

// WithNetmask adds or updates an OptSubnetMask
func WithNetmask(mask net.IPMask) Modifier {
	return WithOption(OptSubnetMask(mask))
}

// WithLeaseTime adds or updates an OptIPAddressLeaseTime
func WithLeaseTime(leaseTime uint32) Modifier {
	return WithOption(OptIPAddressLeaseTime(time.Duration(leaseTime) * time.Second))
}

// WithDomainSearchList adds or updates an OptionDomainSearch
func WithDomainSearchList(searchList ...string) Modifier {
	return WithOption(OptDomainSearch(&rfc1035label.Labels{
		Labels: searchList,
	}))
}

func WithGeneric(code OptionCode, value []byte) Modifier {
	return WithOption(OptGeneric(code, value))
}
