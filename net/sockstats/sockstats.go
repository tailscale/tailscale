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

	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
)

// SockStats contains statistics for sockets instrumented with the
// WithSockStats() function
type SockStats struct {
	Stats                    map[Label]SockStat
	CurrentInterfaceCellular bool
}

// SockStat contains the sent and received bytes for a socket instrumented with
// the WithSockStats() function.
type SockStat struct {
	TxBytes uint64
	RxBytes uint64
}

// Label is an identifier for a socket that stats are collected for. A finite
// set of values that may be used to label a socket to encourage grouping and
// to make storage more efficient.
type Label uint8

//go:generate go run golang.org/x/tools/cmd/stringer -type Label -trimprefix Label

// Labels are named after the package and function/struct that uses the socket.
// Values may be persisted and thus existing entries should not be re-numbered.
const (
	LabelControlClientAuto   Label = 0  // control/controlclient/auto.go
	LabelControlClientDialer Label = 1  // control/controlhttp/client.go
	LabelDERPHTTPClient      Label = 2  // derp/derphttp/derphttp_client.go
	LabelLogtailLogger       Label = 3  // logtail/logtail.go
	LabelDNSForwarderDoH     Label = 4  // net/dns/resolver/forwarder.go
	LabelDNSForwarderUDP     Label = 5  // net/dns/resolver/forwarder.go
	LabelNetcheckClient      Label = 6  // net/netcheck/netcheck.go
	LabelPortmapperClient    Label = 7  // net/portmapper/portmapper.go
	LabelMagicsockConnUDP4   Label = 8  // wgengine/magicsock/magicsock.go
	LabelMagicsockConnUDP6   Label = 9  // wgengine/magicsock/magicsock.go
	LabelNetlogLogger        Label = 10 // wgengine/netlog/logger.go
	LabelSockstatlogLogger   Label = 11 // log/sockstatlog/logger.go
	LabelDNSForwarderTCP     Label = 12 // net/dns/resolver/forwarder.go
)

// WithSockStats instruments a context so that sockets created with it will
// have their statistics collected.
func WithSockStats(ctx context.Context, label Label, logf logger.Logf) context.Context {
	return withSockStats(ctx, label, logf)
}

// Get returns the current socket statistics.
func Get() *SockStats {
	return get()
}

// InterfaceSockStats contains statistics for sockets instrumented with the
// WithSockStats() function, broken down by interface. The statistics may be a
// subset of the total if interfaces were added after the instrumented socket
// was created.
type InterfaceSockStats struct {
	Stats      map[Label]InterfaceSockStat
	Interfaces []string
}

// InterfaceSockStat contains the per-interface sent and received bytes for a
// socket instrumented with the WithSockStats() function.
type InterfaceSockStat struct {
	TxBytesByInterface map[string]uint64
	RxBytesByInterface map[string]uint64
}

// GetWithInterfaces is a variant of Get that returns the current socket
// statistics broken down by interface. It is slightly more expensive than Get.
func GetInterfaces() *InterfaceSockStats {
	return getInterfaces()
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

// GetValidation is a variant of Get that returns external validation numbers
// for stats. It is more expensive than Get and should be used in debug
// interfaces only.
func GetValidation() *ValidationSockStats {
	return getValidation()
}

// SetNetMon configures the sockstats package to monitor the active
// interface, so that per-interface stats can be collected.
func SetNetMon(netMon *netmon.Monitor) {
	setNetMon(netMon)
}

// DebugInfo returns a string containing debug information about the tracked
// statistics.
func DebugInfo() string {
	return debugInfo()
}
