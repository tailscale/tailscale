// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package apitype contains types for the Tailscale LocalAPI and control plane API.
package apitype

import (
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/ctxkey"
)

// LocalAPIHost is the Host header value used by the LocalAPI.
const LocalAPIHost = "local-tailscaled.sock"

// RequestReasonHeader is the header used to pass justification for a LocalAPI request,
// such as when a user wants to perform an action they don't have permission for,
// and a policy allows it with justification. As of 2025-01-29, it is only used to
// allow a user to disconnect Tailscale when the "always-on" mode is enabled.
//
// The header value is base64-encoded using the standard encoding defined in RFC 4648.
//
// See tailscale/corp#26146.
const RequestReasonHeader = "X-Tailscale-Reason"

// RequestReasonKey is the context key used to pass the request reason
// when making a LocalAPI request via [local.Client].
// It's value is a raw string. An empty string means no reason was provided.
//
// See tailscale/corp#26146.
var RequestReasonKey = ctxkey.New(RequestReasonHeader, "")

// WhoIsResponse is the JSON type returned by tailscaled debug server's /whois?ip=$IP handler.
// In successful whois responses, Node and UserProfile are never nil.
type WhoIsResponse struct {
	Node        *tailcfg.Node
	UserProfile *tailcfg.UserProfile

	// CapMap is a map of capabilities to their values.
	// See tailcfg.PeerCapMap and tailcfg.PeerCapability for details.
	CapMap tailcfg.PeerCapMap
}

// FileTarget is a node to which files can be sent, and the PeerAPI
// URL base to do so via.
type FileTarget struct {
	Node *tailcfg.Node

	// PeerAPI is the http://ip:port URL base of the node's PeerAPI,
	// without any path (not even a single slash).
	PeerAPIURL string
}

type WaitingFile struct {
	Name string
	Size int64
}

// SetPushDeviceTokenRequest is the body POSTed to the LocalAPI endpoint /set-device-token.
type SetPushDeviceTokenRequest struct {
	// PushDeviceToken is the iOS/macOS APNs device token (and any future Android equivalent).
	PushDeviceToken string
}

// ReloadConfigResponse is the response to a LocalAPI reload-config request.
//
// There are three possible outcomes: (false, "") if no config mode in use,
// (true, "") on success, or (false, "error message") on failure.
type ReloadConfigResponse struct {
	Reloaded bool   // whether the config was reloaded
	Err      string // any error message
}

// ExitNodeSuggestionResponse is the response to a LocalAPI suggest-exit-node GET request.
// It returns the StableNodeID, name, and location of a suggested exit node for the client making the request.
type ExitNodeSuggestionResponse struct {
	ID       tailcfg.StableNodeID
	Name     string
	Location tailcfg.LocationView `json:",omitempty"`
}

// DNSOSConfig mimics dns.OSConfig without forcing us to import the entire dns package
// into the CLI.
type DNSOSConfig struct {
	Nameservers   []string
	SearchDomains []string
	MatchDomains  []string
}

// DNSQueryResponse is the response to a DNS query request sent via LocalAPI.
type DNSQueryResponse struct {
	// Bytes is the raw DNS response bytes.
	Bytes []byte
	// Resolvers is the list of resolvers that the forwarder deemed able to resolve the query.
	Resolvers []*dnstype.Resolver
}

// OptionalFeatures describes which optional features are enabled in the build.
type OptionalFeatures struct {
	// Features is the map of optional feature names to whether they are
	// enabled.
	//
	// Disabled features may be absent from the map. (That is, false values
	// are not guaranteed to be present.)
	Features map[string]bool
}
