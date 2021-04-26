// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"runtime"
	"strings"
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
func (m *Manager) compileConfig(cfg Config) (resolver.Config, OSConfig, error) {
	// Deal with trivial configs first.
	switch {
	case !cfg.needsOSResolver():
		// Set search domains, but nothing else. This also covers the
		// case where cfg is entirely zero, in which case these
		// configs clear all Tailscale DNS settings.
		return resolver.Config{}, OSConfig{
			SearchDomains: cfg.SearchDomains,
		}, nil
	case cfg.hasDefaultResolversOnly():
		// Trivial CorpDNS configuration, just override the OS
		// resolver.
		return resolver.Config{}, OSConfig{
			Nameservers:   toIPsOnly(cfg.DefaultResolvers),
			SearchDomains: cfg.SearchDomains,
		}, nil
	case cfg.hasDefaultResolvers():
		// Default resolvers plus other stuff always ends up proxying
		// through quad-100.
		rcfg := resolver.Config{
			Routes: map[dnsname.FQDN][]netaddr.IPPort{
				".": cfg.DefaultResolvers,
			},
			Hosts:        cfg.Hosts,
			LocalDomains: cfg.AuthoritativeSuffixes,
		}
		for suffix, resolvers := range cfg.Routes {
			rcfg.Routes[suffix] = resolvers
		}
		ocfg := OSConfig{
			Nameservers:   []netaddr.IP{tsaddr.TailscaleServiceIP()},
			SearchDomains: cfg.SearchDomains,
		}
		return rcfg, ocfg, nil
	}

	// From this point on, we're figuring out split DNS
	// configurations. The possible cases don't return directly any
	// more, because as a final step we have to handle the case where
	// the OS can't do split DNS.
	var rcfg resolver.Config
	var ocfg OSConfig

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

	// The windows check is for
	// . See also below
	// for further routing workarounds there.
	if !cfg.hasHosts() && cfg.singleResolverSet() != nil && m.os.SupportsSplitDNS() && !isWindows {
		// Split DNS configuration requested, where all split domains
		// go to the same resolvers. We can let the OS do it.
		return resolver.Config{}, OSConfig{
			Nameservers:   toIPsOnly(cfg.singleResolverSet()),
			SearchDomains: cfg.SearchDomains,
			MatchDomains:  cfg.matchDomains(),
		}, nil
	}

	// Split DNS configuration with either multiple upstream routes,
	// or routes + MagicDNS, or just MagicDNS, or on an OS that cannot
	// split-DNS. Install a split config pointing at quad-100.
	rcfg = resolver.Config{
		Hosts:        cfg.Hosts,
		LocalDomains: cfg.AuthoritativeSuffixes,
		Routes:       map[dnsname.FQDN][]netaddr.IPPort{},
	}
	for suffix, resolvers := range cfg.Routes {
		rcfg.Routes[suffix] = resolvers
	}
	ocfg = OSConfig{
		Nameservers:   []netaddr.IP{tsaddr.TailscaleServiceIP()},
		SearchDomains: cfg.SearchDomains,
	}

	// If the OS can't do native split-dns, read out the underlying
	// resolver config and blend it into our config.
	if m.os.SupportsSplitDNS() {
		ocfg.MatchDomains = cfg.matchDomains()
	}
	if !m.os.SupportsSplitDNS() || isWindows {
		bcfg, err := m.os.GetBaseConfig()
		if err != nil {
			// Temporary hack to make OSes where split-DNS isn't fully
			// implemented yet not completely crap out, but instead
			// fall back to quad-9 as a hardcoded "backup resolver".
			//
			// This codepath currently only triggers when opted into
			// the split-DNS feature server side, and when at least
			// one search domain is something within tailscale.com, so
			// we don't accidentally leak unstable user DNS queries to
			// quad-9 if we accidentally go down this codepath.
			canUseHack := false
			for _, dom := range cfg.SearchDomains {
				if strings.HasSuffix(dom.WithoutTrailingDot(), ".tailscale.com") {
					canUseHack = true
					break
				}
			}
			if !canUseHack {
				return resolver.Config{}, OSConfig{}, err
			}
			bcfg = OSConfig{
				Nameservers: []netaddr.IP{netaddr.IPv4(9, 9, 9, 9)},
			}
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
		ret = append(ret, ipp.IP)
	}
	return ret
}

func toIPPorts(ips []netaddr.IP) (ret []netaddr.IPPort) {
	ret = make([]netaddr.IPPort, 0, len(ips))
	for _, ip := range ips {
		ret = append(ret, netaddr.IPPort{IP: ip, Port: 53})
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
