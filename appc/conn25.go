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

const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

// DNSAddrScheme is the custom URI scheme used for conn25-managed split DNS
// entries to determine the destination at query time rather than configuration
// time.
const DNSAddrScheme = "tailscale-app"

func AppDNSRoutes(hasCap func(c nodecap.Cap) bool, self tailcfg.NodeView) map[string][]*dnstype.Resolver {
	if !hasCap(AppConnectorsExperimentalAttrName) {
		return nil
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return nil
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
