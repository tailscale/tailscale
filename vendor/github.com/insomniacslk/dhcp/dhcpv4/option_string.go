package dhcpv4

// String represents an option encapsulating a string in IPv4 DHCP.
//
// This representation is shared by multiple options specified by RFC 2132,
// Sections 3.14, 3.16, 3.17, 3.19, and 3.20.
type String string

// ToBytes returns a serialized stream of bytes for this option.
func (o String) ToBytes() []byte {
	return []byte(o)
}

// String returns a human-readable string.
func (o String) String() string {
	return string(o)
}

// FromBytes parses a serialized stream of bytes into o.
func (o *String) FromBytes(data []byte) error {
	*o = String(string(data))
	return nil
}

// GetString parses an RFC 2132 string from o[code].
func GetString(code OptionCode, o Options) string {
	v := o.Get(code)
	if v == nil {
		return ""
	}
	return string(v)
}

// OptDomainName returns a new DHCPv4 Domain Name option.
//
// The Domain Name option is described by RFC 2132, Section 3.17.
func OptDomainName(name string) Option {
	return Option{Code: OptionDomainName, Value: String(name)}
}

// OptHostName returns a new DHCPv4 Host Name option.
//
// The Host Name option is described by RFC 2132, Section 3.14.
func OptHostName(name string) Option {
	return Option{Code: OptionHostName, Value: String(name)}
}

// OptRootPath returns a new DHCPv4 Root Path option.
//
// The Root Path option is described by RFC 2132, Section 3.19.
func OptRootPath(name string) Option {
	return Option{Code: OptionRootPath, Value: String(name)}
}

// OptBootFileName returns a new DHCPv4 Boot File Name option.
//
// The Bootfile Name option is described by RFC 2132, Section 9.5.
func OptBootFileName(name string) Option {
	return Option{Code: OptionBootfileName, Value: String(name)}
}

// OptTFTPServerName returns a new DHCPv4 TFTP Server Name option.
//
// The TFTP Server Name option is described by RFC 2132, Section 9.4.
func OptTFTPServerName(name string) Option {
	return Option{Code: OptionTFTPServerName, Value: String(name)}
}

// OptClassIdentifier returns a new DHCPv4 Class Identifier option.
//
// The Vendor Class Identifier option is described by RFC 2132, Section 9.13.
func OptClassIdentifier(name string) Option {
	return Option{Code: OptionClassIdentifier, Value: String(name)}
}

// OptUserClass returns a new DHCPv4 User Class option.
func OptUserClass(name string) Option {
	return Option{Code: OptionUserClassInformation, Value: String(name)}
}

// OptMessage returns a new DHCPv4 (Error) Message option.
func OptMessage(msg string) Option {
	return Option{Code: OptionMessage, Value: String(msg)}
}
