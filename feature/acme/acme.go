// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package acme registers the ACME/TLS-cert feature and implements its
// associated [ipnext.Extension]. The extension owns the per-LocalBackend
// state previously held in package-level globals and on LocalBackend
// fields (ACME serialization mutex, in-flight cert tracking, etc.).
//
// The cert code that runs against this state still lives in
// [tailscale.com/ipn/ipnlocal]; this extension simply owns the state
// and installs a hook so cert.go can find it from a *LocalBackend.
package acme

import (
	"tailscale.com/feature"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/types/logger"
)

// featureName is the name of the feature implemented by this package.
const featureName = "acme"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
	ipnlocal.HookCertState.Set(certStateFor)
}

func newExtension(logf logger.Logf, _ ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		state: new(ipnlocal.CertState),
		logf:  logger.WithPrefix(logf, featureName+": "),
	}, nil
}

// extension is an [ipnext.Extension] that owns the per-LocalBackend
// ACME/cert state. Most of the cert logic still lives in ipnlocal;
// this extension exists to give that state a non-global home.
type extension struct {
	state *ipnlocal.CertState
	logf  logger.Logf
}

// Name implements [ipnext.Extension].
func (e *extension) Name() string { return featureName }

// Init implements [ipnext.Extension].
func (e *extension) Init(ipnext.Host) error { return nil }

// Shutdown implements [ipnext.Extension].
func (e *extension) Shutdown() error { return nil }

// certStateFor returns the [ipnlocal.CertState] owned by the acme
// extension registered on b, or nil if none.
func certStateFor(b *ipnlocal.LocalBackend) *ipnlocal.CertState {
	e, ok := ipnlocal.GetExt[*extension](b)
	if !ok {
		return nil
	}
	return e.state
}
