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

type SockStats struct {
	Stats      map[Label]SockStat
	Interfaces []string
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

type SockStat struct {
	TxBytes            int64
	RxBytes            int64
	TxBytesByInterface map[string]int64
	RxBytesByInterface map[string]int64
}

func WithSockStats(ctx context.Context, label Label) context.Context {
	return withSockStats(ctx, label)
}

func Get() *SockStats {
	return get()
}

// LinkMonitor is the interface for the parts of wgengine/mointor's Mon that we
// need, to avoid the dependency.
type LinkMonitor interface {
	InterfaceState() *interfaces.State
	RegisterChangeCallback(interfaces.ChangeFunc) (unregister func())
}

func SetLinkMonitor(lm LinkMonitor) {
	setLinkMonitor(lm)
}
