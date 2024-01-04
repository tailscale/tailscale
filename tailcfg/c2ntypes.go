// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// c2n (control-to-node) API types.

package tailcfg

import "net/netip"

// C2NSSHUsernamesRequest is the request for the /ssh/usernames.
// A GET request without a request body is equivalent to the zero value of this type.
// Otherwise, a POST request with a JSON-encoded request body is expected.
type C2NSSHUsernamesRequest struct {
	// Exclude optionally specifies usernames to exclude
	// from the response.
	Exclude map[string]bool `json:",omitempty"`

	// Max is the maximum number of usernames to return.
	// If zero, a default limit is used.
	Max int `json:",omitempty"`
}

// C2NSSHUsernamesResponse is the response (from node to control) from the
// /ssh/usernames handler.
//
// It returns username auto-complete suggestions for a user to SSH to this node.
// It's only shown to people who already have SSH access to the node. If this
// returns multiple usernames, only the usernames that would have access per the
// tailnet's ACLs are shown to the user so as to not leak the existence of
// usernames.
type C2NSSHUsernamesResponse struct {
	// Usernames is the list of usernames to suggest. If the machine has many
	// users, this list may be truncated. If getting the list of usernames might
	// be too slow or unavailable, this list might be empty. This is effectively
	// just a best effort set of hints.
	Usernames []string
}

// C2NUpdateResponse is the response (from node to control) from the /update
// handler. It tells control the status of its request for the node to update
// its Tailscale installation.
type C2NUpdateResponse struct {
	// Err is the error message, if any.
	Err string `json:",omitempty"`

	// Enabled indicates whether the user has opted in to updates triggered from
	// control.
	Enabled bool

	// Supported indicates whether remote updates are supported on this
	// OS/platform.
	Supported bool

	// Started indicates whether the update has started.
	Started bool
}

// C2NPostureIdentityResponse contains either a set of identifying serial number
// from the client or a boolean indicating that the machine has opted out of
// posture collection.
type C2NPostureIdentityResponse struct {
	// SerialNumbers is a list of serial numbers of the client machine.
	SerialNumbers []string `json:",omitempty"`

	// PostureDisabled indicates if the machine has opted out of
	// device posture collection.
	PostureDisabled bool `json:",omitempty"`
}

// C2NAppConnectorDomainRoutesResponse contains a map of domains to
// slice of addresses, indicating what IP addresses have been resolved
// for each domain.
type C2NAppConnectorDomainRoutesResponse struct {
	// Domains is a map of lower case domain names with no trailing dot,
	// to a list of resolved IP addresses.
	Domains map[string][]netip.Addr
}

// C2NTLSCertInfo describes the state of a cached TLS certificate.
type C2NTLSCertInfo struct {
	// Valid means that the node has a cached and valid (not expired)
	// certificate.
	Valid bool `json:",omitempty"`
	// Error is the error string if the certificate is not valid. If error is
	// non-empty, the other booleans below might say why.
	Error string `json:",omitempty"`

	// Missing is whether the error string indicates a missing certificate
	// that's never been fetched or isn't on disk.
	Missing bool `json:",omitempty"`

	// Expired is whether the error string indicates an expired certificate.
	Expired bool `json:",omitempty"`

	NotBefore string `json:",omitempty"` // RFC3339, if Valid
	NotAfter  string `json:",omitempty"` // RFC3339, if Valid

	// TODO(bradfitz): add fields for whether an ACME fetch is currently in
	// process and when it started, etc.
}
