// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"runtime"
	"time"

	"inet.af/netaddr"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
	"tailscale.com/wgengine/monitor"
)

// We use file-ignore below instead of ignore because on some platforms,
// the lint exception is necessary and on others it is not,
// and plain ignore complains if the exception is unnecessary.

//lint:file-ignore U1000 reconfigTimeout is used on some platforms but not others

// reconfigTimeout is the time interval within which Manager.{Up,Down} should complete.
//
// This is particularly useful because certain conditions can cause indefinite hangs
// (such as improper dbus auth followed by contextless dbus.Object.Call).
// Such operations should be wrapped in a timeout context.
const reconfigTimeout = time.Second

// Manager manages system DNS settings.
type Manager struct {
	logf logger.Logf

	resolver *resolver.Resolver
	os       OSConfigurator

	config Config
}

// NewManagers created a new manager from the given config.
func NewManager(logf logger.Logf, oscfg OSConfigurator, linkMon *monitor.Mon) *Manager {
	logf = logger.WithPrefix(logf, "dns: ")
	m := &Manager{
		logf:     logf,
		resolver: resolver.New(logf, linkMon),
		os:       oscfg,
	}
	m.logf("using %T", m.os)
	return m
}

func (m *Manager) Set(cfg Config) error {
	m.logf("Set: %+v", cfg)

	rcfg, ocfg, err := m.compileConfig(cfg)
	if err != nil {
		return err
	}

	m.logf("Resolvercfg: %+v", rcfg)
	m.logf("OScfg: %+v", ocfg)

	if err := m.resolver.SetConfig(rcfg); err != nil {
		return err
	}
	if err := m.os.SetDNS(ocfg); err != nil {
		return err
	}

	return nil
}

// compileConfig converts cfg into a quad-100 resolver configuration
// and an OS-level configuration.
func (m *Manager) compileConfig(cfg Config) (rcfg resolver.Config, ocfg OSConfig, err error) {
	// The internal resolver always gets MagicDNS hosts and
	// authoritative suffixes, even if we don't propagate MagicDNS to
	// the OS.
	rcfg.Hosts = cfg.Hosts
	routes := map[dnsname.FQDN][]netaddr.IPPort{} // assigned conditionally to rcfg.Routes below.
	for suffix, resolvers := range cfg.Routes {
		if len(resolvers) == 0 {
			rcfg.LocalDomains = append(rcfg.LocalDomains, suffix)
		} else {
			routes[suffix] = resolvers
		}
	}
	// Similarly, the OS always gets search paths.
	ocfg.SearchDomains = cfg.SearchDomains

	// Deal with trivial configs first.
	switch {
	case !cfg.needsOSResolver():
		// Set search domains, but nothing else. This also covers the
		// case where cfg is entirely zero, in which case these
		// configs clear all Tailscale DNS settings.
		return rcfg, ocfg, nil
	case cfg.hasDefaultResolversOnly():
		// Trivial CorpDNS configuration, just override the OS
		// resolver.
		ocfg.Nameservers = toIPsOnly(cfg.DefaultResolvers)
		return rcfg, ocfg, nil
	case cfg.hasDefaultResolvers():
		// Default resolvers plus other stuff always ends up proxying
		// through quad-100.
		rcfg.Routes = routes
		rcfg.Routes["."] = cfg.DefaultResolvers
		ocfg.Nameservers = []netaddr.IP{tsaddr.TailscaleServiceIP()}
		return rcfg, ocfg, nil
	}

	// From this point on, we're figuring out split DNS
	// configurations. The possible cases don't return directly any
	// more, because as a final step we have to handle the case where
	// the OS can't do split DNS.

	// Workaround for
	// https://github.com/tailscale/corp/issues/1662. Even though
	// Windows natively supports split DNS, it only configures linux
	// containers using whatever the primary is, and doesn't apply
	// NRPT rules to DNS traffic coming from WSL.
	//
	// In order to make WSL work okay when the host Windows is using
	// Tailscale, we need to set up quad-100 as a "full proxy"
	// resolver, regardless of whether Windows itself can do split
	// DNS. We still make Windows do split DNS itself when it can, but
	// quad-100 will still have the full split configuration as well,
	// and so can service WSL requests correctly.
	//
	// This bool is used in a couple of places below to implement this
	// workaround.
	isWindows := runtime.GOOS == "windows"
	if cfg.singleResolverSet() != nil && m.os.SupportsSplitDNS() && !isWindows {
		// Split DNS configuration requested, where all split domains
		// go to the same resolvers. We can let the OS do it.
		ocfg.Nameservers = toIPsOnly(cfg.singleResolverSet())
		ocfg.MatchDomains = cfg.matchDomains()
		return rcfg, ocfg, nil
	}

	// Split DNS configuration with either multiple upstream routes,
	// or routes + MagicDNS, or just MagicDNS, or on an OS that cannot
	// split-DNS. Install a split config pointing at quad-100.
	rcfg.Routes = routes
	ocfg.Nameservers = []netaddr.IP{tsaddr.TailscaleServiceIP()}

	// If the OS can't do native split-dns, read out the underlying
	// resolver config and blend it into our config.
	if m.os.SupportsSplitDNS() {
		ocfg.MatchDomains = cfg.matchDomains()
	}
	if !m.os.SupportsSplitDNS() || isWindows {
		bcfg, err := m.os.GetBaseConfig()
		if err != nil {
			return resolver.Config{}, OSConfig{}, err
		}
		rcfg.Routes["."] = toIPPorts(bcfg.Nameservers)
		ocfg.SearchDomains = append(ocfg.SearchDomains, bcfg.SearchDomains...)
	}

	return rcfg, ocfg, nil
}

// toIPsOnly returns only the IP portion of ipps.
// TODO: this discards port information on the assumption that we're
// always pointing at port 53.
// https://github.com/tailscale/tailscale/issues/1666 tracks making
// that not true, if we ever want to.
func toIPsOnly(ipps []netaddr.IPPort) (ret []netaddr.IP) {
	ret = make([]netaddr.IP, 0, len(ipps))
	for _, ipp := range ipps {
		ret = append(ret, ipp.IP())
	}
	return ret
}

func toIPPorts(ips []netaddr.IP) (ret []netaddr.IPPort) {
	ret = make([]netaddr.IPPort, 0, len(ips))
	for _, ip := range ips {
		ret = append(ret, netaddr.IPPortFrom(ip, 53))
	}
	return ret
}

func (m *Manager) EnqueueRequest(bs []byte, from netaddr.IPPort) error {
	return m.resolver.EnqueueRequest(bs, from)
}

func (m *Manager) NextResponse() ([]byte, netaddr.IPPort, error) {
	return m.resolver.NextResponse()
}

func (m *Manager) Down() error {
	if err := m.os.Close(); err != nil {
		return err
	}
	m.resolver.Close()
	return nil
}

// Cleanup restores the system DNS configuration to its original state
// in case the Tailscale daemon terminated without closing the router.
// No other state needs to be instantiated before this runs.
func Cleanup(logf logger.Logf, interfaceName string) {
	oscfg, err := NewOSConfigurator(logf, interfaceName)
	if err != nil {
		logf("creating dns cleanup: %v", err)
		return
	}
	dns := NewManager(logf, oscfg, nil)
	if err := dns.Down(); err != nil {
		logf("dns down: %v", err)
	}
}
