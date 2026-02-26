// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache

import (
	"tailscale.com/tailcfg"
	"tailscale.com/tka"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
)

// The fields in the following wrapper types are all pointers, even when their
// target type is also a pointer, so that they can be used to unmarshal
// directly into the fields of another value.  These wrappers intentionally do
// not omit zero or empty values, since we want the cache to reflect the value
// the object had at the time it was written, even if the default changes
// later.
//
// Moreover, these are all struct types so that each cached record will be a
// JSON object even if the underlying value marshals to an array or primitive
// type, and so that we have a seam if we want to replace or version the cached
// representation separately from the default JSON layout.

type netmapMisc struct {
	MachineKey       *key.MachinePublic
	CollectServices  *bool
	DisplayMessages  *map[tailcfg.DisplayMessageID]tailcfg.DisplayMessage
	TKAEnabled       *bool
	TKAHead          *tka.AUMHash
	Domain           *string
	DomainAuditLogID *string
}

type netmapSSH struct {
	SSHPolicy **tailcfg.SSHPolicy
}

type netmapDNS struct {
	DNS *tailcfg.DNSConfig
}

type netmapDERPMap struct {
	DERPMap **tailcfg.DERPMap
}

type netmapNode struct {
	Node *tailcfg.NodeView
}

type netmapUserProfile struct {
	UserProfile *tailcfg.UserProfileView
}

type netmapPacketFilter struct {
	Rules *views.Slice[tailcfg.FilterRule]

	// Match expressions are derived from the rules.
}
