// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package blockblame blames specific firewall manufacturers for blocking Tailscale,
// by analyzing the SSL certificate presented when attempting to connect to a remote
// server.
package blockblame

import (
	"crypto/x509"
	"strings"
)

// VerifyCertificate checks if the given certificate c is issued by a firewall manufacturer
// that is known to block Tailscale connections. It returns true and the Manufacturer of
// the equipment if it is, or false and nil if it is not.
func VerifyCertificate(c *x509.Certificate) (m *Manufacturer, ok bool) {
	for _, m := range Manufacturers {
		if m.match != nil && m.match(c) {
			return m, true
		}
	}
	return nil, false
}

// Manufacturer represents a firewall manufacturer that may be blocking Tailscale.
type Manufacturer struct {
	// Name is the name of the firewall manufacturer to be
	// mentioned in health warning messages, e.g. "Fortinet".
	Name string
	// match is a function that returns true if the given certificate looks like it might
	// be issued by this manufacturer.
	match matchFunc
}

var Manufacturers = []*Manufacturer{
	{
		Name:  "Aruba Networks",
		match: issuerContains("Aruba"),
	},
	{
		Name:  "Cisco",
		match: issuerContains("Cisco"),
	},
	{
		Name: "Fortinet",
		match: matchAny(
			issuerContains("Fortinet"),
			certEmail("support@fortinet.com"),
		),
	},
	{
		Name:  "Huawei",
		match: certEmail("mobile@huawei.com"),
	},
	{
		Name: "Palo Alto Networks",
		match: matchAny(
			issuerContains("Palo Alto Networks"),
			issuerContains("PAN-FW"),
		),
	},
	{
		Name:  "Sophos",
		match: issuerContains("Sophos"),
	},
	{
		Name: "Ubiquiti",
		match: matchAny(
			issuerContains("UniFi"),
			issuerContains("Ubiquiti"),
		),
	},
}

type matchFunc func(*x509.Certificate) bool

func issuerContains(s string) matchFunc {
	return func(c *x509.Certificate) bool {
		return strings.Contains(strings.ToLower(c.Issuer.String()), strings.ToLower(s))
	}
}

func certEmail(v string) matchFunc {
	return func(c *x509.Certificate) bool {
		for _, email := range c.EmailAddresses {
			if strings.Contains(strings.ToLower(email), strings.ToLower(v)) {
				return true
			}
		}
		return false
	}
}

func matchAny(fs ...matchFunc) matchFunc {
	return func(c *x509.Certificate) bool {
		for _, f := range fs {
			if f(c) {
				return true
			}
		}
		return false
	}
}
