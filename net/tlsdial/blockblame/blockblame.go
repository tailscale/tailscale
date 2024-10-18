// Package blockblame blames specific firewall manufacturers for blocking Tailscale,
// by analyzing the SSL certificate presented when attempting to connect to a remote
// server.
package blockblame

import (
	"crypto/x509"
	"strings"
)

// Manufacturer represents a firewall manufacturer that may be blocking Tailscale.
type Manufacturer struct {
	// Name of the firewall manufacturer, e.g. "Fortinet"
	CompanyName string
	// List of indicators that can be used to identify the manufacturer
	Indicators []Indicator
}

// Indicator represents a specific piece of information within a SSL certificate that can be
// used to identify the manufacturer of a firewall.
type Indicator struct {
	IssuerName string // never empty, matches if Issuer contains this
	EmailAddr  string // may be empty, matches if EmailAddresses contains this
}

var Manufacturers = []Manufacturer{
	{
		CompanyName: "Aruba Networks",
		Indicators: []Indicator{
			{
				IssuerName: "Aruba",
			},
		},
	},
	{
		CompanyName: "Fortinet",
		Indicators: []Indicator{
			{
				IssuerName: "Fortinet",
				EmailAddr:  "support@fortinet.com",
			},
		},
	},
	{
		CompanyName: "Palo Alto Networks",
		Indicators: []Indicator{
			{
				IssuerName: "Palo Alto Networks",
			},
		},
	},
	{
		CompanyName: "Sophos",
		Indicators: []Indicator{
			{
				IssuerName: "Sophos",
			},
		},
	},
	// Fake entry for testing purposes (see blockblame_test.go)
	{
		CompanyName: "Fake Testing Manufacturer Ltd.",
		Indicators: []Indicator{
			{
				IssuerName: "Tailscale Test Test Test",
				EmailAddr:  "test@tailscale.com",
			},
		},
	},
}

// VerifyCertificate checks if the given certificate is issued by a firewall manufacturer
// that is known to block Tailscale connections. It returns true and the Manufacturer of
// the equipment if it is, or false and nil if it is not.
func VerifyCertificate(cert *x509.Certificate) (m *Manufacturer, found bool) {
	for _, m := range Manufacturers {
		for _, i := range m.Indicators {
			if strings.Contains(cert.Issuer.String(), i.IssuerName) {
				return &m, true
			}
			for _, email := range cert.EmailAddresses {
				if strings.Contains(email, i.EmailAddr) {
					return &m, true
				}
			}
		}
	}
	return nil, false
}
