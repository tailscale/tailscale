// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"time"

	"inet.af/netaddr"
	"tailscale.com/net/dns/resolver"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
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

	if len(cfg.DefaultResolvers) == 0 {
		// TODO: make other settings work even if you didn't set a
		// default resolver. For now, no default resolvers == no
		// managed DNS config.
		cfg = Config{}
	}

	resolverCfg := resolver.Config{
		Hosts:        cfg.Hosts,
		LocalDomains: cfg.AuthoritativeSuffixes,
		Routes:       map[string][]netaddr.IPPort{},
	}
	osCfg := OSConfig{
		SearchDomains: cfg.SearchDomains,
	}
	// We must proxy through quad-100 if MagicDNS hosts are in
	// use, or there are any per-domain routes.
	mustProxy := len(cfg.Hosts) > 0 || len(cfg.Routes) > 0
	if mustProxy {
		osCfg.Nameservers = []netaddr.IP{tsaddr.TailscaleServiceIP()}
		resolverCfg.Routes["."] = cfg.DefaultResolvers
		for suffix, resolvers := range cfg.Routes {
			resolverCfg.Routes[suffix] = resolvers
		}
	} else {
		for _, resolver := range cfg.DefaultResolvers {
			osCfg.Nameservers = append(osCfg.Nameservers, resolver.IP)
		}
	}

	if err := m.resolver.SetConfig(resolverCfg); err != nil {
		return err
	}
	if err := m.os.SetDNS(osCfg); err != nil {
		return err
	}

	return nil
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
	oscfg := NewOSConfigurator(logf, interfaceName)
	dns := NewManager(logf, oscfg, nil)
	if err := dns.Down(); err != nil {
		logf("dns down: %v", err)
	}
}
