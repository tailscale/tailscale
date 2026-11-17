// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_appconnectors

package ipnlocal

import (
	"net/netip"

	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

// appcAppConnector stands in for [tailscale.com/appc.AppConnector] in
// builds without app connectors, so that this package does not import
// appc. Its methods exist only so that the shared code in local.go type
// checks; they are never reached, because every caller first checks
// [buildfeatures.HasAppConnectors] and b.appConnector is always nil.
type appcAppConnector struct{}

func newAppConnector(logf logger.Logf, bus *eventbus.Bus, ri *appctype.RouteInfo, storeRoutes bool) *appcAppConnector {
	panic("unreachable with ts_omit_appconnectors")
}

func (*appcAppConnector) Close()                                                         {}
func (*appcAppConnector) ShouldStoreRoutes() bool                                        { return false }
func (*appcAppConnector) UpdateDomainsAndRoutes(domains []string, routes []netip.Prefix) {}
func (*appcAppConnector) DomainRoutes() map[string][]netip.Addr                          { return nil }
func (*appcAppConnector) ObserveDNSResponse(res []byte) error                            { return nil }
func (*appcAppConnector) ClearRoutes() error                                             { return nil }

// AppConnector returns nil; app connectors are omitted from this build.
func (b *LocalBackend) AppConnector() *appcAppConnector { return nil }
