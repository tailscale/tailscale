// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package controlhttp

import (
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"tailscale.com/health"
	"tailscale.com/net/dnscache"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netx"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	// serverUpgradePath is where the server-side HTTP handler to
	// to do the protocol switch is located.
	serverUpgradePath = "/ts2021"
)

// NoPort is a sentinel value for Dialer.HTTPSPort to indicate that HTTPS
// should not be tried on any port. It exists primarily for some localhost
// tests where the control plane only runs on HTTP.
const NoPort = "none"

// Dialer contains configuration on how to dial the Tailscale control server.
type Dialer struct {
	// Hostname is the hostname to connect to, with no port number.
	//
	// This field is required.
	Hostname string

	// MachineKey contains the current machine's private key.
	//
	// This field is required.
	MachineKey key.MachinePrivate

	// ControlKey contains the expected public key for the control server.
	//
	// This field is required.
	ControlKey key.MachinePublic

	// ProtocolVersion is the expected protocol version to negotiate.
	//
	// This field is required.
	ProtocolVersion uint16

	// HTTPPort is the port number to use when making a HTTP connection.
	//
	// If not specified, this defaults to port 80.
	HTTPPort string

	// HTTPSPort is the port number to use when making a HTTPS connection.
	//
	// If not specified, this defaults to port 443.
	//
	// If "none" (NoPort), HTTPS is disabled.
	HTTPSPort string

	// Dialer is the dialer used to make outbound connections.
	//
	// If not specified, this defaults to net.Dialer.DialContext.
	Dialer netx.DialFunc

	// DNSCache is the caching Resolver used by this Dialer.
	//
	// If not specified, a new Resolver is created per attempt.
	DNSCache *dnscache.Resolver

	// Logf, if set, is a logging function to use; if unset, logs are
	// dropped.
	Logf logger.Logf

	// NetMon is the [netmon.Monitor] to use for this Dialer. It must be
	// non-nil.
	NetMon *netmon.Monitor

	// HealthTracker, if non-nil, is the health tracker to use.
	HealthTracker *health.Tracker

	// DialPlan, if set, contains instructions from the control server on
	// how to connect to it. If present, we will try the methods in this
	// plan before falling back to DNS.
	DialPlan *tailcfg.ControlDialPlan

	proxyFunc func(*http.Request) (*url.URL, error) // or nil

	// logPort80Failure is whether we should log about port 80 interceptions
	// and forcing a port 443 dial. We do this only once per "dial" method
	// which can result in many concurrent racing dialHost calls.
	logPort80Failure atomic.Bool

	// For tests only
	omitCertErrorLogging bool
	testFallbackDelay    time.Duration

	// Clock, if non-nil, overrides the clock to use.
	// If nil, tstime.StdClock is used.
	// This exists primarily for tests.
	Clock tstime.Clock
}

func strDef(v1, v2 string) string {
	if v1 != "" {
		return v1
	}
	return v2
}
