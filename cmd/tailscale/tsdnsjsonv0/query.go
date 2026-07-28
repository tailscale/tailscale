// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdnsjsonv0

// Answer is a single DNS resource record from a query response.
type Answer struct {
	Name  string
	TTL   uint32
	Class string // e.g. "ClassINET"
	Type  string // e.g. "TypeA", "TypeAAAA"
	Body  string // human-readable record data
}

// QueryResponse is the result of a DNS query via the Tailscale
// internal forwarder (100.100.100.100). It is the output of:
//
//	$ tailscale dns query --json NAME
type QueryResponse struct {
	Name         string
	QueryType    string         // e.g. "A", "AAAA"
	Resolvers    []ResolverInfo `json:",omitzero"`
	ResponseCode string         // e.g. "RCodeSuccess", "RCodeNameError"
	Answers      []Answer       `json:",omitzero"`
}
