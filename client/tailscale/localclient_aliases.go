// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tailscale

import (
	"context"
	"crypto/tls"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
)

// ErrPeerNotFound is an alias for [tailscale.com/client/local.ErrPeerNotFound].
//
// Deprecated: import [tailscale.com/client/local] instead.
var ErrPeerNotFound = local.ErrPeerNotFound

// LocalClient is an alias for [tailscale.com/client/local.Client].
//
// Deprecated: import [tailscale.com/client/local] instead.
type LocalClient = local.Client

// IPNBusWatcher is an alias for [tailscale.com/client/local.IPNBusWatcher].
//
// Deprecated: import [tailscale.com/client/local] instead.
type IPNBusWatcher = local.IPNBusWatcher

// BugReportOpts is an alias for [tailscale.com/client/local.BugReportOpts].
//
// Deprecated: import [tailscale.com/client/local] instead.
type BugReportOpts = local.BugReportOpts

// DebugPortmapOpts is an alias for [tailscale.com/client/local.DebugPortmapOpts].
//
// Deprecated: import [tailscale.com/client/local] instead.
type DebugPortmapOpts = local.DebugPortmapOpts

// PingOpts is an alias for [tailscale.com/client/local.PingOpts].
//
// Deprecated: import [tailscale.com/client/local] instead.
type PingOpts = local.PingOpts

// GetCertificate is an alias for [tailscale.com/client/local.GetCertificate].
//
// Deprecated: import [tailscale.com/client/local] instead and use [local.Client.GetCertificate].
func GetCertificate(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return local.GetCertificate(hi)
}

// SetVersionMismatchHandler is an alias for [tailscale.com/client/local.SetVersionMismatchHandler].
//
// Deprecated: import [tailscale.com/client/local] instead.
func SetVersionMismatchHandler(f func(clientVer, serverVer string)) {
	local.SetVersionMismatchHandler(f)
}

// IsAccessDeniedError is an alias for [tailscale.com/client/local.IsAccessDeniedError].
//
// Deprecated: import [tailscale.com/client/local] instead.
func IsAccessDeniedError(err error) bool {
	return local.IsAccessDeniedError(err)
}

// IsPreconditionsFailedError is an alias for [tailscale.com/client/local.IsPreconditionsFailedError].
//
// Deprecated: import [tailscale.com/client/local] instead.
func IsPreconditionsFailedError(err error) bool {
	return local.IsPreconditionsFailedError(err)
}

// WhoIs is an alias for [tailscale.com/client/local.WhoIs].
//
// Deprecated: import [tailscale.com/client/local] instead and use [local.Client.WhoIs].
func WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return local.WhoIs(ctx, remoteAddr)
}

// Status is an alias for [tailscale.com/client/local.Status].
//
// Deprecated: import [tailscale.com/client/local] instead.
func Status(ctx context.Context) (*ipnstate.Status, error) {
	return local.Status(ctx)
}

// StatusWithoutPeers is an alias for [tailscale.com/client/local.StatusWithoutPeers].
//
// Deprecated: import [tailscale.com/client/local] instead.
func StatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	return local.StatusWithoutPeers(ctx)
}

// CertPair is an alias for [tailscale.com/client/local.CertPair].
//
// Deprecated: import [tailscale.com/client/local] instead and use [local.Client.CertPair].
func CertPair(ctx context.Context, domain string) (certPEM, keyPEM []byte, err error) {
	return local.CertPair(ctx, domain)
}

// ExpandSNIName is an alias for [tailscale.com/client/local.ExpandSNIName].
//
// Deprecated: import [tailscale.com/client/local] instead and use [local.Client.ExpandSNIName].
func ExpandSNIName(ctx context.Context, name string) (fqdn string, ok bool) {
	return local.ExpandSNIName(ctx, name)
}
