package dhcpv4

// OptMessageType returns a new DHCPv4 Message Type option.
func OptMessageType(m MessageType) Option {
	return Option{Code: OptionDHCPMessageType, Value: m}
}
