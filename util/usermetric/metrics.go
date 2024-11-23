// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file contains user-facing metrics that are used by multiple packages.
// Use it to define more common metrics. Any changes to the registry and
// metric types should be in usermetric.go.

package usermetric

import (
	"sync"

	"tailscale.com/metrics"
)

// Metrics contains user-facing metrics that are used by multiple packages.
type Metrics struct {
	initOnce sync.Once

	droppedPacketsInbound  *metrics.MultiLabelMap[DropLabels]
	droppedPacketsOutbound *metrics.MultiLabelMap[DropLabels]
}

// DropReason is the reason why a packet was dropped.
type DropReason string

const (
	// ReasonACL means that the packet was not permitted by ACL.
	ReasonACL DropReason = "acl"

	// ReasonError means that the packet was dropped because of an error.
	ReasonError DropReason = "error"
)

// DropLabels contains common label(s) for dropped packet counters.
type DropLabels struct {
	Reason DropReason
}

// initOnce initializes the common metrics.
func (r *Registry) initOnce() {
	r.m.initOnce.Do(func() {
		r.m.droppedPacketsInbound = NewMultiLabelMapWithRegistry[DropLabels](
			r,
			"tailscaled_inbound_dropped_packets_total",
			"counter",
			"Counts the number of dropped packets received by the node from other peers",
		)
		r.m.droppedPacketsOutbound = NewMultiLabelMapWithRegistry[DropLabels](
			r,
			"tailscaled_outbound_dropped_packets_total",
			"counter",
			"Counts the number of packets dropped while being sent to other peers",
		)
	})
}

// DroppedPacketsOutbound returns the outbound dropped packet metric, creating it
// if necessary.
func (r *Registry) DroppedPacketsOutbound() *metrics.MultiLabelMap[DropLabels] {
	r.initOnce()
	return r.m.droppedPacketsOutbound
}

// DroppedPacketsInbound returns the inbound dropped packet metric.
func (r *Registry) DroppedPacketsInbound() *metrics.MultiLabelMap[DropLabels] {
	r.initOnce()
	return r.m.droppedPacketsInbound
}
