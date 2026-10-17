// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"fmt"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/appctype"
	"tailscale.com/types/dnstype"
)

const AppConnectorAttrName = "tailscale.com/app-connectors"
const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

// DNSAddrScheme is the custom URI scheme used for conn25-managed split DNS
// entries to determine the destination at query time rather than configuration
// time.
const DNSAddrScheme = "tailscale-app"

// AppDNSRoutes returns split DNS routes, keyed by domain suffix, for the app
// domains configured in self's capability map. Each route resolves via the
// [DNSAddrScheme] scheme naming the app, so the connector that serves it is
// chosen at query time. It returns nil if the node lacks Connectors 2025 apps.
func AppDNSRoutes(hasCap func(c nodecap.Cap) bool, self tailcfg.NodeView) map[string][]*dnstype.Resolver {
	if !hasCap(AppConnectorsExperimentalAttrName) && !hasCap(AppConnectorAttrName) {
		return nil
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return nil
	}

	// In addition to the apps under the [AppConnectorsExperimentalAttrName],
	// apps can also be provided  under [AppConnectorAttrName] with the Mode
	// field set to "magicip".
	unfilteredApps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorAttrName)
	if err != nil {
		return nil
	}
	for _, app := range unfilteredApps {
		if app.Mode == "magicip" {
			apps = append(apps, app)
		}
	}

	appNamesByDomain := map[string]string{}
	for _, app := range apps {
		for _, domain := range app.Domains {
			domain, _ = strings.CutPrefix(domain, "*.")
			domain = strings.ToLower(domain)
			// in the case of multiple apps specifying the same domain (which is misconfiguration
			// that should be validated at point of input) last write wins.
			appNamesByDomain[domain] = app.Name
		}
	}
	m := make(map[string][]*dnstype.Resolver, len(appNamesByDomain))
	for domain, appName := range appNamesByDomain {
		m[domain] = []*dnstype.Resolver{{Addr: fmt.Sprintf("%s:%s", DNSAddrScheme, appName), UseWithExitNode: true}}
	}
	return m
}
