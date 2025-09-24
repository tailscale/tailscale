// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains user-facing metrics that are used by multiple packages.
// Use it to define more common metrics. Any changes to the registry and
// metric types should be in usermetric.go.

package usermetric

import (
	"sync"
)

// Metrics contains user-facing metrics that are used by multiple packages.
type Metrics struct {
	initOnce sync.Once
}

// DropReason is the reason why a packet was dropped.
type DropReason string

const (
	// ReasonACL means that the packet was not permitted by ACL.
	ReasonACL DropReason = "acl"

	// ReasonMulticast means that the packet was dropped because it was a multicast packet.
	ReasonMulticast DropReason = "multicast"

	// ReasonLinkLocalUnicast means that the packet was dropped because it was a link-local unicast packet.
	ReasonLinkLocalUnicast DropReason = "link_local_unicast"

	// ReasonTooShort means that the packet was dropped because it was a bad packet,
	// this could be due to a short packet.
	ReasonTooShort DropReason = "too_short"

	// ReasonFragment means that the packet was dropped because it was an IP fragment.
	ReasonFragment DropReason = "fragment"

	// ReasonUnknownProtocol means that the packet was dropped because it was an unknown protocol.
	ReasonUnknownProtocol DropReason = "unknown_protocol"

	// ReasonError means that the packet was dropped because of an error.
	ReasonError DropReason = "error"
)

// DropLabels contains common label(s) for dropped packet counters.
type DropLabels struct {
	Reason DropReason
}

// DroppedPacketsOutbound returns the outbound dropped packet metric, creating it
// if necessary.
func (r *Registry) DroppedPacketsOutbound() *MultiLabelMap[DropLabels] {
	return &MultiLabelMap[DropLabels]{}
}

// DroppedPacketsInbound returns the inbound dropped packet metric.
func (r *Registry) DroppedPacketsInbound() *MultiLabelMap[DropLabels] {
	return &MultiLabelMap[DropLabels]{}
}
