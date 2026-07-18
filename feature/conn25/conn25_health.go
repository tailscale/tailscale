// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package conn25

import (
	"tailscale.com/feature/appconnectors/appchealth"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/util/dnsname"
)

// onBackendStateChange implements the [ipnext.Hooks.BackendStateChange] hook. A
// node that isn't running serves no app connector DNS, so clear the warning; it
// is recomputed on the way back up.
func (e *extension) onBackendStateChange(state ipn.State) {
	if state != ipn.Running {
		if ht := e.healthTracker(); ht != nil {
			appchealth.SetHealthy(ht, &e.dnsHealth)
		}
	}
}

// updateDNSHealth refreshes the app connector DNS health warning from conn25's
// current config and the last-seen accept-DNS pref.
func (e *extension) updateDNSHealth() {
	ht := e.healthTracker()
	if ht == nil {
		return
	}
	res := e.resolver()
	if res == nil {
		appchealth.SetHealthy(ht, &e.dnsHealth)
		return
	}
	appchealth.Update(ht, &e.dnsHealth, e.conn25.logf, e.acceptDNS, e.conn25.selfConnectorDomains(), func(fqdn dnsname.FQDN) bool {
		return len(res.GetUpstreamResolvers(fqdn)) > 0
	})
}

func (e *extension) healthTracker() *health.Tracker {
	if e.backend == nil {
		return nil
	}
	ht, _ := e.backend.Sys().HealthTracker.GetOK()
	return ht
}

func (e *extension) resolver() *resolver.Resolver {
	if e.backend == nil {
		return nil
	}
	mgr, ok := e.backend.Sys().DNSManager.GetOK()
	if !ok {
		return nil
	}
	return mgr.Resolver()
}

// selfConnectorDomains returns the domains this node serves as a conn25 app
// connector: the (non-wildcard) domains of the apps whose connectors match the
// self node's tags.
func (c *Conn25) selfConnectorDomains() []string {
	cfg, ok := c.getConfig()
	if !ok {
		return nil
	}
	var domains []string
	for domain, appNames := range cfg.appNamesByDomain {
		for _, appName := range appNames {
			if cfg.selfAppNames.Contains(appName) {
				domains = append(domains, domain.WithoutTrailingDot())
				break
			}
		}
	}
	return domains
}
