// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package appconnectors registers support for Tailscale App Connectors.
package appconnectors

import (
	"encoding/json"
	"net/http"
	"slices"

	"tailscale.com/feature"
	"tailscale.com/feature/appconnectors/appchealth"
	"tailscale.com/health"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnext"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/appctype"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

// featureName is the name of the feature implemented by this package.
// It is also the [ipnext.Extension] name and the log prefix.
const featureName = "appconnectors"

// appConnectorCapName is the node capability carrying app connector config.
const appConnectorCapName = "tailscale.com/app-connectors"

func init() {
	feature.Register(featureName)
	ipnext.RegisterExtension(featureName, newExtension)
	ipnlocal.RegisterC2N("GET /appconnector/routes", handleC2NAppConnectorDomainRoutesGet)
}

// extension is the [ipnext.Extension] for classic app connectors. Today it only
// reports the app connector DNS health warning ([appchealth]); the rest of the
// classic app connector still lives in [ipnlocal.LocalBackend].
type extension struct {
	logf    logger.Logf
	backend ipnext.SafeBackend
	host    ipnext.Host // set in Init, read-only after

	// The following are accessed only from the extension's hooks, which the
	// host invokes synchronously (never concurrently), so they need no lock.

	// advertise and acceptDNS are the last-seen prefs, updated by
	// profileStateChange.
	advertise bool
	acceptDNS bool
	// domains is the set of domains the self node advertises as an app
	// connector, updated by onSelfChange.
	domains []string
	// dnsHealth is the edge-trigger state for the health warning.
	dnsHealth appchealth.State
}

func newExtension(logf logger.Logf, sb ipnext.SafeBackend) (ipnext.Extension, error) {
	return &extension{
		logf:    logger.WithPrefix(logf, featureName+": "),
		backend: sb,
	}, nil
}

func (e *extension) Name() string { return featureName }

func (e *extension) Init(host ipnext.Host) error {
	e.host = host
	host.Hooks().OnSelfChange.Add(e.onSelfChange)
	host.Hooks().ProfileStateChange.Add(e.profileStateChange)
	host.Hooks().BackendStateChange.Add(e.onBackendStateChange)
	return nil
}

func (e *extension) Shutdown() error { return nil }

// onSelfChange implements the [ipnext.Hooks.OnSelfChange] hook. It recomputes
// the set of domains this node advertises as an app connector and refreshes the
// DNS health warning.
func (e *extension) onSelfChange(self tailcfg.NodeView) {
	e.domains = advertisedDomains(self)
	e.updateDNSHealth()
}

// profileStateChange implements the [ipnext.Hooks.ProfileStateChange] hook.
func (e *extension) profileStateChange(_ ipn.LoginProfileView, prefs ipn.PrefsView, _ bool) {
	e.advertise = prefs.Valid() && prefs.AppConnector().Advertise
	e.acceptDNS = prefs.Valid() && prefs.CorpDNS()
	e.updateDNSHealth()
}

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

// updateDNSHealth refreshes the app connector DNS health warning from the
// extension's current view of prefs and advertised domains.
func (e *extension) updateDNSHealth() {
	ht := e.healthTracker()
	if ht == nil {
		return
	}
	if !e.advertise {
		appchealth.SetHealthy(ht, &e.dnsHealth)
		return
	}
	res := e.resolver()
	if res == nil {
		appchealth.SetHealthy(ht, &e.dnsHealth)
		return
	}
	appchealth.Update(ht, &e.dnsHealth, e.logf, e.acceptDNS, e.domains, func(fqdn dnsname.FQDN) bool {
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

// advertisedDomains returns the sorted, de-duplicated set of domains that self
// advertises as an app connector, per its "tailscale.com/app-connectors"
// capability. It mirrors the collection in
// [ipnlocal.LocalBackend.reconfigAppConnectorLocked].
func advertisedDomains(self tailcfg.NodeView) []string {
	if !self.Valid() {
		return nil
	}
	attrs, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), appConnectorCapName)
	if err != nil {
		return nil
	}
	selfHasTag := func(attrTags []string) bool {
		return self.Tags().ContainsFunc(func(tag string) bool {
			return slices.Contains(attrTags, tag)
		})
	}
	var domains []string
	for _, attr := range attrs {
		if slices.Contains(attr.Connectors, "*") || selfHasTag(attr.Connectors) {
			domains = append(domains, attr.Domains...)
		}
	}
	slices.Sort(domains)
	return slices.Compact(domains)
}

// handleC2NAppConnectorDomainRoutesGet handles returning the domains
// that the app connector is responsible for, as well as the resolved
// IP addresses for each domain. If the node is not configured as
// an app connector, an empty map is returned.
func handleC2NAppConnectorDomainRoutesGet(b *ipnlocal.LocalBackend, w http.ResponseWriter, r *http.Request) {
	logf := b.Logger()
	logf("c2n: GET /appconnector/routes received")

	var res tailcfg.C2NAppConnectorDomainRoutesResponse
	appConnector := b.AppConnector()
	if appConnector == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
		return
	}

	res.Domains = appConnector.DomainRoutes()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
