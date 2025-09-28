// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && !ts_omit_resolved

package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/util/dnsname"
)

// DBus entities we talk to.
//
// DBus is an RPC bus. In particular, the bus we're talking to is the
// system-wide bus (there is also a per-user session bus for
// user-specific applications).
//
// Daemons connect to the bus, and advertise themselves under a
// well-known object name. That object exposes paths, and each path
// implements one or more interfaces that contain methods, properties,
// and signals.
//
// Clients connect to the bus and walk that same hierarchy to invoke
// RPCs, get/set properties, or listen for signals.
const (
	dbusResolvedObject                    = "org.freedesktop.resolve1"
	dbusResolvedPath      dbus.ObjectPath = "/org/freedesktop/resolve1"
	dbusResolvedInterface                 = "org.freedesktop.resolve1.Manager"
	dbusPath              dbus.ObjectPath = "/org/freedesktop/DBus"
	dbusInterface                         = "org.freedesktop.DBus"
	dbusOwnerSignal                       = "NameOwnerChanged" // broadcast when a well-known name's owning process changes.
)

type resolvedLinkNameserver struct {
	Family  int32
	Address []byte
}

type resolvedLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

// changeRequest tracks latest OSConfig and related error responses to update.
type changeRequest struct {
	config OSConfig     // configs OSConfigs, one per each SetDNS call
	res    chan<- error // response channel
}

// resolvedManager is an OSConfigurator which uses the systemd-resolved DBus API.
type resolvedManager struct {
	ctx    context.Context
	cancel func() // terminate the context, for close

	logf   logger.Logf
	health *health.Tracker
	ifidx  int

	configCR chan changeRequest // tracks OSConfigs changes and error responses
}

func init() {
	optNewResolvedManager.Set(newResolvedManager)
}

func newResolvedManager(logf logger.Logf, health *health.Tracker, interfaceName string) (OSConfigurator, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	logf = logger.WithPrefix(logf, "dns: ")

	mgr := &resolvedManager{
		ctx:    ctx,
		cancel: cancel,

		logf:   logf,
		health: health,
		ifidx:  iface.Index,

		configCR: make(chan changeRequest),
	}

	go mgr.run(ctx)

	return mgr, nil
}

func (m *resolvedManager) SetDNS(config OSConfig) error {
	// NOTE: don't close this channel, since it's possible that the SetDNS
	// call will time out and return before the run loop answers, at which
	// point it will send on the now-closed channel.
	errc := make(chan error, 1)

	select {
	case <-m.ctx.Done():
		return m.ctx.Err()
	case m.configCR <- changeRequest{config, errc}:
	}

	select {
	case <-m.ctx.Done():
		return m.ctx.Err()
	case err := <-errc:
		if err != nil {
			m.logf("failed to configure resolved: %v", err)
		}
		return err
	}
}

func (m *resolvedManager) run(ctx context.Context) {
	var (
		conn     *dbus.Conn
		signals  chan *dbus.Signal
		rManager dbus.BusObject // rManager is the Resolved DBus connection
	)
	bo := backoff.NewBackoff("resolved-dbus", m.logf, 30*time.Second)
	needsReconnect := make(chan bool, 1)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	// Reconnect the systemBus if disconnected.
	reconnect := func() error {
		var err error
		signals = make(chan *dbus.Signal, 16)
		conn, err = dbus.SystemBus()
		if err != nil {
			m.logf("dbus connection error: %v", err)
		} else {
			m.logf("[v1] dbus connected")
		}

		if err != nil {
			// Backoff increases time between reconnect attempts.
			go func() {
				bo.BackOff(ctx, err)
				needsReconnect <- true
			}()
			return err
		}

		rManager = conn.Object(dbusResolvedObject, dbus.ObjectPath(dbusResolvedPath))

		// Only receive the DBus signals we need to resync our config on
		// resolved restart. Failure to set filters isn't a fatal error,
		// we'll just receive all broadcast signals and have to ignore
		// them on our end.
		if err = conn.AddMatchSignal(dbus.WithMatchObjectPath(dbusPath), dbus.WithMatchInterface(dbusInterface), dbus.WithMatchMember(dbusOwnerSignal), dbus.WithMatchArg(0, dbusResolvedObject)); err != nil {
			m.logf("[v1] Setting DBus signal filter failed: %v", err)
		}
		conn.Signal(signals)

		// Reset backoff and set osConfigurationSetWarnable to healthy after a successful reconnect.
		bo.BackOff(ctx, nil)
		m.health.SetHealthy(osConfigurationSetWarnable)
		return nil
	}

	// Create initial systemBus connection.
	reconnect()

	lastConfig := OSConfig{}

	for {
		select {
		case <-ctx.Done():
			if rManager == nil {
				return
			}
			// RevertLink resets all per-interface settings on systemd-resolved to defaults.
			// When ctx goes away systemd-resolved auto reverts.
			// Keeping for potential use in future refactor.
			if call := rManager.CallWithContext(ctx, dbusResolvedInterface+".RevertLink", 0, m.ifidx); call.Err != nil {
				m.logf("[v1] RevertLink: %v", call.Err)
				return
			}
			return
		case configCR := <-m.configCR:
			// Track and update sync with latest config change.
			lastConfig = configCR.config

			if rManager == nil {
				configCR.res <- fmt.Errorf("resolved DBus does not have a connection")
				continue
			}
			err := m.setConfigOverDBus(ctx, rManager, configCR.config)
			configCR.res <- err
		case <-needsReconnect:
			if err := reconnect(); err != nil {
				m.logf("[v1] SystemBus reconnect error %T", err)
			}
			continue
		case signal, ok := <-signals:
			// If signal ends and is nil then program tries to reconnect.
			if !ok {
				if err := reconnect(); err != nil {
					m.logf("[v1] SystemBus reconnect error %T", err)
				}
				continue
			}
			// In theory the signal was filtered by DBus, but if
			// AddMatchSignal in the constructor failed, we may be
			// getting other spam.
			if signal.Path != dbusPath || signal.Name != dbusInterface+"."+dbusOwnerSignal {
				continue
			}
			if lastConfig.IsZero() {
				continue
			}
			// signal.Body is a []any of 3 strings: bus name, previous owner, new owner.
			if len(signal.Body) != 3 {
				m.logf("[unexpected] DBus NameOwnerChanged len(Body) = %d, want 3")
			}
			if name, ok := signal.Body[0].(string); !ok || name != dbusResolvedObject {
				continue
			}
			newOwner, ok := signal.Body[2].(string)
			if !ok {
				m.logf("[unexpected] DBus NameOwnerChanged.new_owner is a %T, not a string", signal.Body[2])
			}
			if newOwner == "" {
				// systemd-resolved left the bus, no current owner,
				// nothing to do.
				continue
			}
			// The resolved bus name has a new owner, meaning resolved
			// restarted. Reprogram current config.
			m.logf("systemd-resolved restarted, syncing DNS config")
			err := m.setConfigOverDBus(ctx, rManager, lastConfig)
			// Set health while holding the lock, because this will
			// graciously serialize the resync's health outcome with a
			// concurrent SetDNS call.

			if err != nil {
				m.logf("failed to configure systemd-resolved: %v", err)
				m.health.SetUnhealthy(osConfigurationSetWarnable, health.Args{health.ArgError: err.Error()})
			} else {
				m.health.SetHealthy(osConfigurationSetWarnable)
			}
		}
	}
}

// setConfigOverDBus updates resolved DBus config and is only called from the run goroutine.
func (m *resolvedManager) setConfigOverDBus(ctx context.Context, rManager dbus.BusObject, config OSConfig) error {
	ctx, cancel := context.WithTimeout(ctx, reconfigTimeout)
	defer cancel()

	var linkNameservers = make([]resolvedLinkNameserver, len(config.Nameservers))
	for i, server := range config.Nameservers {
		ip := server.As16()
		if server.Is4() {
			linkNameservers[i] = resolvedLinkNameserver{
				Family:  unix.AF_INET,
				Address: ip[12:],
			}
		} else {
			linkNameservers[i] = resolvedLinkNameserver{
				Family:  unix.AF_INET6,
				Address: ip[:],
			}
		}
	}
	err := rManager.CallWithContext(
		ctx, dbusResolvedInterface+".SetLinkDNS", 0,
		m.ifidx, linkNameservers,
	).Store()
	if err != nil {
		return fmt.Errorf("setLinkDNS: %w", err)
	}
	linkDomains := make([]resolvedLinkDomain, 0, len(config.SearchDomains)+len(config.MatchDomains))
	seenDomains := map[dnsname.FQDN]bool{}
	for _, domain := range config.SearchDomains {
		if seenDomains[domain] {
			continue
		}
		seenDomains[domain] = true
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      domain.WithTrailingDot(),
			RoutingOnly: false,
		})
	}
	for _, domain := range config.MatchDomains {
		if seenDomains[domain] {
			// Search domains act as both search and match in
			// resolved, so it's correct to skip.
			continue
		}
		seenDomains[domain] = true
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      domain.WithTrailingDot(),
			RoutingOnly: true,
		})
	}
	if len(config.MatchDomains) == 0 && len(config.Nameservers) > 0 {
		// Caller requested full DNS interception, install a
		// routing-only root domain.
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      ".",
			RoutingOnly: true,
		})
	}

	err = rManager.CallWithContext(
		ctx, dbusResolvedInterface+".SetLinkDomains", 0,
		m.ifidx, linkDomains,
	).Store()
	if err != nil && err.Error() == "Argument list too long" { // TODO: better error match
		// Issue 3188: older systemd-resolved had argument length limits.
		// Trim out the *.arpa. entries and try again.
		err = rManager.CallWithContext(
			ctx, dbusResolvedInterface+".SetLinkDomains", 0,
			m.ifidx, linkDomainsWithoutReverseDNS(linkDomains),
		).Store()
	}
	if err != nil {
		return fmt.Errorf("setLinkDomains: %w", err)
	}

	if call := rManager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDefaultRoute", 0, m.ifidx, len(config.MatchDomains) == 0); call.Err != nil {
		if dbusErr, ok := call.Err.(dbus.Error); ok && dbusErr.Name == dbus.ErrMsgUnknownMethod.Name {
			// on some older systems like Kubuntu 18.04.6 with systemd 237 method SetLinkDefaultRoute is absent,
			// but otherwise it's working good
			m.logf("[v1] failed to set SetLinkDefaultRoute: %v", call.Err)
		} else {
			return fmt.Errorf("setLinkDefaultRoute: %w", call.Err)
		}
	}

	// Some best-effort setting of things, but resolved should do the
	// right thing if these fail (e.g. a really old resolved version
	// or something).

	// Disable LLMNR, we don't do multicast.
	if call := rManager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkLLMNR", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable LLMNR: %v", call.Err)
	}

	// Disable mdns.
	if call := rManager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkMulticastDNS", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable mdns: %v", call.Err)
	}

	// We don't support dnssec consistently right now, force it off to
	// avoid partial failures when we split DNS internally.
	if call := rManager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDNSSEC", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DNSSEC: %v", call.Err)
	}

	if call := rManager.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDNSOverTLS", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DoT: %v", call.Err)
	}

	if call := rManager.CallWithContext(ctx, dbusResolvedInterface+".FlushCaches", 0); call.Err != nil {
		m.logf("failed to flush resolved DNS cache: %v", call.Err)
	}
	return nil
}

func (m *resolvedManager) SupportsSplitDNS() bool {
	return true
}

func (m *resolvedManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, ErrGetBaseConfigNotSupported
}

func (m *resolvedManager) Close() error {
	m.cancel() // stops the 'run' method goroutine
	return nil
}

// linkDomainsWithoutReverseDNS returns a copy of v without
// *.arpa. entries.
func linkDomainsWithoutReverseDNS(v []resolvedLinkDomain) (ret []resolvedLinkDomain) {
	for _, d := range v {
		if strings.HasSuffix(d.Domain, ".arpa.") {
			// Oh well. At least the rest will work.
			continue
		}
		ret = append(ret, d)
	}
	return ret
}
