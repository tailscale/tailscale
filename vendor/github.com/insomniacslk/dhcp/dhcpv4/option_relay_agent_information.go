package dhcpv4

import (
	"fmt"
)

// RelayOptions is like Options, but stringifies using the Relay Agent Specific
// option space.
type RelayOptions struct {
	Options
}

var relayHumanizer = OptionHumanizer{
	ValueHumanizer: func(code OptionCode, data []byte) fmt.Stringer {
		return raiSubOptionValue{data}
	},
	CodeHumanizer: func(c uint8) OptionCode {
		return raiSubOptionCode(c)
	},
}

// String prints the contained options using Relay Agent-specific option code parsing.
func (r RelayOptions) String() string {
	return "\n" + r.Options.ToString(relayHumanizer)
}

// FromBytes parses relay agent options from data.
func (r *RelayOptions) FromBytes(data []byte) error {
	r.Options = make(Options)
	return r.Options.FromBytes(data)
}

// OptRelayAgentInfo returns a new DHCP Relay Agent Info option.
//
// The relay agent info option is described by RFC 3046.
func OptRelayAgentInfo(o ...Option) Option {
	return Option{Code: OptionRelayAgentInformation, Value: RelayOptions{OptionsFromList(o...)}}
}

type raiSubOptionValue struct {
	val []byte
}

func (rv raiSubOptionValue) String() string {
	return fmt.Sprintf("%s (%v)", string(rv.val), rv.val)
}

type raiSubOptionCode uint8

func (o raiSubOptionCode) Code() uint8 {
	return uint8(o)
}

func (o raiSubOptionCode) String() string {
	if s, ok := raiSubOptionCodeToString[o]; ok {
		return s
	}
	return fmt.Sprintf("unknown (%d)", o)
}

// Option 82 Relay Agention Information Sub Options
const (
	AgentCircuitIDSubOption                raiSubOptionCode = 1   // RFC 3046
	AgentRemoteIDSubOption                 raiSubOptionCode = 2   // RFC 3046
	DOCSISDeviceClassSubOption             raiSubOptionCode = 4   // RFC 3256
	LinkSelectionSubOption                 raiSubOptionCode = 5   // RFC 3527
	SubscriberIDSubOption                  raiSubOptionCode = 6   // RFC 3993
	RADIUSAttributesSubOption              raiSubOptionCode = 7   // RFC 4014
	AuthenticationSubOption                raiSubOptionCode = 8   // RFC 4030
	VendorSpecificInformationSubOption     raiSubOptionCode = 9   // RFC 4243
	RelayAgentFlagsSubOption               raiSubOptionCode = 10  // RFC 5010
	ServerIdentifierOverrideSubOption      raiSubOptionCode = 11  // RFC 5107
	RelaySourcePortSubOption               raiSubOptionCode = 19  // RFC 8357
	VirtualSubnetSelectionSubOption        raiSubOptionCode = 151 // RFC 6607
	VirtualSubnetSelectionControlSubOption raiSubOptionCode = 152 // RFC 6607
)

var raiSubOptionCodeToString = map[raiSubOptionCode]string{
	AgentCircuitIDSubOption:                "Agent Circuit ID Sub-option",
	AgentRemoteIDSubOption:                 "Agent Remote ID Sub-option",
	DOCSISDeviceClassSubOption:             "DOCSIS Device Class Sub-option",
	LinkSelectionSubOption:                 "Link Selection Sub-option",
	SubscriberIDSubOption:                  "Subscriber ID Sub-option",
	RADIUSAttributesSubOption:              "RADIUS Attributes Sub-option",
	AuthenticationSubOption:                "Authentication Sub-option",
	VendorSpecificInformationSubOption:     "Vendor Specific Sub-option",
	RelayAgentFlagsSubOption:               "Relay Agent Flags Sub-option",
	ServerIdentifierOverrideSubOption:      "Server Identifier Override Sub-option",
	RelaySourcePortSubOption:               "Relay Source Port Sub-option",
	VirtualSubnetSelectionSubOption:        "Virtual Subnet Selection Sub-option",
	VirtualSubnetSelectionControlSubOption: "Virtual Subnet Selection Control Sub-option",
}
