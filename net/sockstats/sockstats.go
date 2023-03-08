// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package sockstats collects statistics about network sockets used by
// the Tailscale client. The context where sockets are used must be
// instrumented with the WithSockStats() function.
//
// Only available on POSIX platforms when built with Tailscale's fork of Go.
package sockstats

import (
	"context"

	"tailscale.com/net/interfaces"
)

// SockStats contains statistics for sockets instrumented with the
// WithSockStats() function, along with the interfaces that we have
// per-interface statistics for.
type SockStats struct {
	Stats                    map[Label]SockStat
	Interfaces               []string
	CurrentInterfaceCellular bool
}

// SockStat contains the sent and received bytes for a socket instrumented with
// the WithSockStats() function. The bytes are also broken down by interface,
// though this may be a subset of the total if interfaces were added after the
// instrumented socket was created.
type SockStat struct {
	TxBytes            uint64
	RxBytes            uint64
	TxBytesByInterface map[string]uint64
	RxBytesByInterface map[string]uint64
}

// Label is an identifier for a socket that stats are collected for. A finite
// set of values that may be used to label a socket to encourage grouping and
// to make storage more efficient.
type Label uint8

//go:generate go run golang.org/x/tools/cmd/stringer -type Label -trimprefix Label

// Labels are named after the package and function/struct that uses the socket.
// Values may be persisted and thus existing entries should not be re-numbered.
const (
	LabelControlClientAuto   Label = 0 // control/controlclient/auto.go
	LabelControlClientDialer Label = 1 // control/controlhttp/client.go
	LabelDERPHTTPClient      Label = 2 // derp/derphttp/derphttp_client.go
	LabelLogtailLogger       Label = 3 // logtail/logtail.go
	LabelDNSForwarderDoH     Label = 4 // net/dns/resolver/forwarder.go
	LabelDNSForwarderUDP     Label = 5 // net/dns/resolver/forwarder.go
	LabelNetcheckClient      Label = 6 // net/netcheck/netcheck.go
	LabelPortmapperClient    Label = 7 // net/portmapper/portmapper.go
	LabelMagicsockConnUDP4   Label = 8 // wgengine/magicsock/magicsock.go
	LabelMagicsockConnUDP6   Label = 9 // wgengine/magicsock/magicsock.go
)

// WithSockStats instruments a context so that sockets created with it will
// have their statistics collected.
func WithSockStats(ctx context.Context, label Label) context.Context {
	return withSockStats(ctx, label)
}

// Get returns the current socket statistics.
func Get() *SockStats {
	return get()
}

// ValidationSockStats contains external validation numbers for sockets
// instrumented with WithSockStats. It may be a subset of the all sockets,
// depending on what externa measurement mechanisms the platform supports.
type ValidationSockStats struct {
	Stats map[Label]ValidationSockStat
}

// ValidationSockStat contains the validation bytes for a socket instrumented
// with WithSockStats.
type ValidationSockStat struct {
	TxBytes uint64
	RxBytes uint64
}

// GetWithValidation is a variant of GetWith that returns both the current stats
// and external validation numbers for the stats. It is more expensive than
// Get and should be used in debug interfaces only.
func GetWithValidation() (*SockStats, *ValidationSockStats) {
	return get(), getValidation()
}

// LinkMonitor is the interface for the parts of wgengine/mointor's Mon that we
// need, to avoid the dependency.
type LinkMonitor interface {
	InterfaceState() *interfaces.State
	RegisterChangeCallback(interfaces.ChangeFunc) (unregister func())
}

// SetLinkMonitor configures the sockstats package to monitor the active
// interface, so that per-interface stats can be collected.
func SetLinkMonitor(lm LinkMonitor) {
	setLinkMonitor(lm)
}
