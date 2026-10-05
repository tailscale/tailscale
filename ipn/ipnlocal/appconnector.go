// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_appconnectors

package ipnlocal

import (
	"tailscale.com/appc"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// appcAppConnector is [appc.AppConnector] in builds that include app
// connectors. Builds with ts_omit_appconnectors substitute a stub type
// (see appconnector_omit.go) so that this package does not import appc
// at all, which keeps appc and its dependencies out of those binaries.
type appcAppConnector = appc.AppConnector

// newAppConnector returns a new [appc.AppConnector] publishing to bus,
// seeded with the previously stored routes in ri (which may be nil).
func newAppConnector(logf logger.Logf, bus *eventbus.Bus, ri *appctype.RouteInfo, storeRoutes bool) *appcAppConnector {
	return appc.NewAppConnector(appc.Config{
		Logf:            logf,
		EventBus:        bus,
		RouteInfo:       ri,
		HasStoredRoutes: storeRoutes,
	})
}

// AppConnector returns the current AppConnector, or nil if not configured.
//
// TODO(nickkhyl): move app connectors to [nodeBackend], or perhaps a feature package?
func (b *LocalBackend) AppConnector() *appc.AppConnector {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.appConnector
}
