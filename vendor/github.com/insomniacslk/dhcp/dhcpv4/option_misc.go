package dhcpv4

import (
	"github.com/insomniacslk/dhcp/iana"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

// OptDomainSearch returns a new domain search option.
//
// The domain search option is described by RFC 3397, Section 2.
func OptDomainSearch(labels *rfc1035label.Labels) Option {
	return Option{Code: OptionDNSDomainSearchList, Value: labels}
}

// OptClientArch returns a new Client System Architecture Type option.
func OptClientArch(archs ...iana.Arch) Option {
	return Option{Code: OptionClientSystemArchitectureType, Value: iana.Archs(archs)}
}

// OptClientIdentifier returns a new Client Identifier option.
func OptClientIdentifier(ident []byte) Option {
	return OptGeneric(OptionClientIdentifier, ident)
}
