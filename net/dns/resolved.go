// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
	"inet.af/netaddr"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
)

// resolvedListenAddr is the listen address of the resolved stub resolver.
//
// We only consider resolved to be the system resolver if the stub resolver is;
// that is, if this address is the sole nameserver in /etc/resolved.conf.
// In other cases, resolved may be managing the system DNS configuration directly.
// Then the nameserver list will be a concatenation of those for all
// the interfaces that register their interest in being a default resolver with
//   SetLinkDomains([]{{"~.", true}, ...})
// which includes at least the interface with the default route, i.e. not us.
// This does not work for us: there is a possibility of getting NXDOMAIN
// from the other nameservers before we are asked or get a chance to respond.
// We consider this case as lacking resolved support and fall through to dnsDirect.
//
// While it may seem that we need to read a config option to get at this,
// this address is, in fact, hard-coded into resolved.
var resolvedListenAddr = netaddr.IPv4(127, 0, 0, 53)

var errNotReady = errors.New("interface not ready")

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

// isResolvedActive determines if resolved is currently managing system DNS settings.
func isResolvedActive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		// Probably no DBus on the system, or we're not allowed to use
		// it. Cannot control resolved.
		return false
	}

	rd := conn.Object("org.freedesktop.resolve1", dbus.ObjectPath("/org/freedesktop/resolve1"))
	call := rd.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	if call.Err != nil {
		// Can't talk to resolved.
		return false
	}

	config, err := newDirectManager(logger.Discard).readResolvFile(resolvConf)
	if err != nil {
		return false
	}

	// The sole nameserver must be the systemd-resolved stub.
	if len(config.Nameservers) == 1 && config.Nameservers[0] == resolvedListenAddr {
		return true
	}

	return false
}

// resolvedManager is an OSConfigurator which uses the systemd-resolved DBus API.
type resolvedManager struct {
	logf  logger.Logf
	ifidx int

	cancelSyncer context.CancelFunc // run to shut down syncer goroutine
	syncerDone   chan struct{}      // closed when syncer is stopped
	resolved     dbus.BusObject

	mu     sync.Mutex // guards RPCs made by syncLocked, and the following
	config OSConfig   // last SetDNS config
}

func newResolvedManager(logf logger.Logf, interfaceName string) (*resolvedManager, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	ret := &resolvedManager{
		logf:         logf,
		ifidx:        iface.Index,
		cancelSyncer: cancel,
		syncerDone:   make(chan struct{}),
		resolved:     conn.Object(dbusResolvedObject, dbus.ObjectPath(dbusResolvedPath)),
	}
	signals := make(chan *dbus.Signal, 16)
	go ret.resync(ctx, signals)
	// Only receive the DBus signals we need to resync our config on
	// resolved restart. Failure to set filters isn't a fatal error,
	// we'll just receive all broadcast signals and have to ignore
	// them on our end.
	if err := conn.AddMatchSignal(dbus.WithMatchObjectPath(dbusPath), dbus.WithMatchInterface(dbusInterface), dbus.WithMatchMember(dbusOwnerSignal), dbus.WithMatchArg(0, dbusResolvedObject)); err != nil {
		logf("[v1] Setting DBus signal filter failed: %v", err)
	}
	conn.Signal(signals)
	return ret, nil
}

func (m *resolvedManager) SetDNS(config OSConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = config
	return m.syncLocked(context.TODO()) // would be nice to plumb context through from SetDNS
}

func (m *resolvedManager) resync(ctx context.Context, signals chan *dbus.Signal) {
	defer close(m.syncerDone)
	for {
		select {
		case <-ctx.Done():
			return
		case signal := <-signals:
			// In theory the signal was filtered by DBus, but if
			// AddMatchSignal in the constructor failed, we may be
			// getting other spam.
			if signal.Path != dbusPath || signal.Name != dbusInterface+"."+dbusOwnerSignal {
				continue
			}
			// signal.Body is a []interface{} of 3 strings: bus name, previous owner, new owner.
			if len(signal.Body) != 3 {
				m.logf("[unexpectected] DBus NameOwnerChanged len(Body) = %d, want 3")
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
			m.mu.Lock()
			err := m.syncLocked(ctx)
			// Set health while holding the lock, because this will
			// graciously serialize the resync's health outcome with a
			// concurrent SetDNS call.
			health.SetDNSOSHealth(err)
			m.mu.Unlock()
			if err != nil {
				m.logf("failed to configure systemd-resolved: %v", err)
			}
		}
	}
}

func (m *resolvedManager) syncLocked(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, reconfigTimeout)
	defer cancel()

	var linkNameservers = make([]resolvedLinkNameserver, len(m.config.Nameservers))
	for i, server := range m.config.Nameservers {
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

	err := m.resolved.CallWithContext(
		ctx, dbusResolvedInterface+".SetLinkDNS", 0,
		m.ifidx, linkNameservers,
	).Store()
	if err != nil {
		return fmt.Errorf("setLinkDNS: %w", err)
	}

	linkDomains := make([]resolvedLinkDomain, 0, len(m.config.SearchDomains)+len(m.config.MatchDomains))
	seenDomains := map[dnsname.FQDN]bool{}
	for _, domain := range m.config.SearchDomains {
		if seenDomains[domain] {
			continue
		}
		seenDomains[domain] = true
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      domain.WithTrailingDot(),
			RoutingOnly: false,
		})
	}
	for _, domain := range m.config.MatchDomains {
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
	if len(m.config.MatchDomains) == 0 && len(m.config.Nameservers) > 0 {
		// Caller requested full DNS interception, install a
		// routing-only root domain.
		linkDomains = append(linkDomains, resolvedLinkDomain{
			Domain:      ".",
			RoutingOnly: true,
		})
	}

	err = m.resolved.CallWithContext(
		ctx, dbusResolvedInterface+".SetLinkDomains", 0,
		m.ifidx, linkDomains,
	).Store()
	if err != nil && err.Error() == "Argument list too long" { // TODO: better error match
		// Issue 3188: older systemd-resolved had argument length limits.
		// Trim out the *.arpa. entries and try again.
		err = m.resolved.CallWithContext(
			ctx, dbusResolvedInterface+".SetLinkDomains", 0,
			m.ifidx, linkDomainsWithoutReverseDNS(linkDomains),
		).Store()
	}
	if err != nil {
		return fmt.Errorf("setLinkDomains: %w", err)
	}

	if call := m.resolved.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDefaultRoute", 0, m.ifidx, len(m.config.MatchDomains) == 0); call.Err != nil {
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
	if call := m.resolved.CallWithContext(ctx, dbusResolvedInterface+".SetLinkLLMNR", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable LLMNR: %v", call.Err)
	}

	// Disable mdns.
	if call := m.resolved.CallWithContext(ctx, dbusResolvedInterface+".SetLinkMulticastDNS", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable mdns: %v", call.Err)
	}

	// We don't support dnssec consistently right now, force it off to
	// avoid partial failures when we split DNS internally.
	if call := m.resolved.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDNSSEC", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DNSSEC: %v", call.Err)
	}

	if call := m.resolved.CallWithContext(ctx, dbusResolvedInterface+".SetLinkDNSOverTLS", 0, m.ifidx, "no"); call.Err != nil {
		m.logf("[v1] failed to disable DoT: %v", call.Err)
	}

	if call := m.resolved.CallWithContext(ctx, dbusResolvedInterface+".FlushCaches", 0); call.Err != nil {
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
	m.cancelSyncer()

	ctx, cancel := context.WithTimeout(context.Background(), reconfigTimeout)
	defer cancel()
	if call := m.resolved.CallWithContext(ctx, dbusResolvedInterface+".RevertLink", 0, m.ifidx); call.Err != nil {
		return fmt.Errorf("RevertLink: %w", call.Err)
	}

	select {
	case <-m.syncerDone:
	case <-ctx.Done():
		m.logf("timeout in systemd-resolved syncer shutdown")
	}

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
