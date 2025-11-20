// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package dns

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"tailscale.com/control/controlknobs"
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	"tailscale.com/health"
	"tailscale.com/net/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/version/distro"
)

type kv struct {
	k, v string
}

func (kv kv) String() string {
	return fmt.Sprintf("%s=%s", kv.k, kv.v)
}

var publishOnce sync.Once

// reconfigTimeout is the time interval within which Manager.{Up,Down} should complete.
//
// This is particularly useful because certain conditions can cause indefinite hangs
// (such as improper dbus auth followed by contextless dbus.Object.Call).
// Such operations should be wrapped in a timeout context.
const reconfigTimeout = time.Second

// Set unless ts_omit_networkmanager
var (
	optNewNMManager      feature.Hook[func(ifName string) (OSConfigurator, error)]
	optNMIsUsingResolved feature.Hook[func() error]
	optNMVersionBetween  feature.Hook[func(v1, v2 string) (bool, error)]
)

// Set unless ts_omit_resolved
var (
	optNewResolvedManager feature.Hook[func(logf logger.Logf, health *health.Tracker, interfaceName string) (OSConfigurator, error)]
)

// Set unless ts_omit_dbus
var (
	optDBusPing       feature.Hook[func(name, objectPath string) error]
	optDBusReadString feature.Hook[func(name, objectPath, iface, member string) (string, error)]
)

// NewOSConfigurator created a new OS configurator.
//
// The health tracker may be nil; the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logf logger.Logf, health *health.Tracker, _ policyclient.Client, _ *controlknobs.Knobs, interfaceName string) (ret OSConfigurator, err error) {
	if !buildfeatures.HasDNS || distro.Get() == distro.JetKVM {
		return NewNoopManager()
	}

	env := newOSConfigEnv{
		fs:              directFS{},
		resolvconfStyle: resolvconfStyle,
	}
	if f, ok := optDBusPing.GetOk(); ok {
		env.dbusPing = f
	} else {
		env.dbusPing = func(_, _ string) error { return errors.ErrUnsupported }
	}
	if f, ok := optDBusReadString.GetOk(); ok {
		env.dbusReadString = f
	} else {
		env.dbusReadString = func(_, _, _, _ string) (string, error) { return "", errors.ErrUnsupported }
	}
	if f, ok := optNMIsUsingResolved.GetOk(); ok {
		env.nmIsUsingResolved = f
	} else {
		env.nmIsUsingResolved = func() error { return errors.ErrUnsupported }
	}
	env.nmVersionBetween, _ = optNMVersionBetween.GetOk() // GetOk to not panic if nil; unused if optNMIsUsingResolved returns an error
	mode, err := dnsMode(logf, health, env)
	if err != nil {
		return nil, err
	}
	publishOnce.Do(func() {
		sanitizedMode := strings.ReplaceAll(mode, "-", "_")
		m := clientmetric.NewGauge(fmt.Sprintf("dns_manager_linux_mode_%s", sanitizedMode))
		m.Set(1)
	})
	logf("dns: using %q mode", mode)
	switch mode {
	case "direct":
		return newDirectManagerOnFS(logf, health, env.fs), nil
	case "systemd-resolved":
		if f, ok := optNewResolvedManager.GetOk(); ok {
			return f(logf, health, interfaceName)
		}
		return nil, fmt.Errorf("tailscaled was built without DNS %q support", mode)
	case "network-manager":
		if f, ok := optNewNMManager.GetOk(); ok {
			return f(interfaceName)
		}
		return nil, fmt.Errorf("tailscaled was built without DNS %q support", mode)
	case "debian-resolvconf":
		return newDebianResolvconfManager(logf)
	case "openresolv":
		return newOpenresolvManager(logf)
	default:
		logf("[unexpected] detected unknown DNS mode %q, using direct manager as last resort", mode)
	}

	return newDirectManagerOnFS(logf, health, env.fs), nil
}

// newOSConfigEnv are the funcs newOSConfigurator needs, pulled out for testing.
type newOSConfigEnv struct {
	fs                wholeFileFS
	dbusPing          func(string, string) error
	dbusReadString    func(string, string, string, string) (string, error)
	nmIsUsingResolved func() error
	nmVersionBetween  func(v1, v2 string) (safe bool, err error)
	resolvconfStyle   func() string
}

func dnsMode(logf logger.Logf, health *health.Tracker, env newOSConfigEnv) (ret string, err error) {
	var debug []kv
	dbg := func(k, v string) {
		debug = append(debug, kv{k, v})
	}
	defer func() {
		if ret != "" {
			dbg("ret", ret)
		}
		logf("dns: %v", debug)
	}()

	// In all cases that we detect systemd-resolved, try asking it what it
	// thinks the current resolv.conf mode is so we can add it to our logs.
	defer func() {
		if ret != "systemd-resolved" {
			return
		}

		// Try to ask systemd-resolved what it thinks the current
		// status of resolv.conf is. This is documented at:
		//    https://www.freedesktop.org/software/systemd/man/org.freedesktop.resolve1.html
		mode, err := env.dbusReadString("org.freedesktop.resolve1", "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager", "ResolvConfMode")
		if err != nil {
			logf("dns: ResolvConfMode error: %v", err)
			dbg("resolv-conf-mode", "error")
		} else {
			dbg("resolv-conf-mode", mode)
		}
	}()

	// Before we read /etc/resolv.conf (which might be in a broken
	// or symlink-dangling state), try to ping the D-Bus service
	// for systemd-resolved. If it's active on the machine, this
	// will make it start up and write the /etc/resolv.conf file
	// before it replies to the ping. (see how systemd's
	// src/resolve/resolved.c calls manager_write_resolv_conf
	// before the sd_event_loop starts)
	resolvedUp := env.dbusPing("org.freedesktop.resolve1", "/org/freedesktop/resolve1") == nil
	if resolvedUp {
		dbg("resolved-ping", "yes")
	}

	bs, err := env.fs.ReadFile(resolvConf)
	if os.IsNotExist(err) {
		dbg("rc", "missing")
		return "direct", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	switch resolvOwner(bs) {
	case "systemd-resolved":
		dbg("rc", "resolved")

		// Some systems, for reasons known only to them, have a
		// resolv.conf that has the word "systemd-resolved" in its
		// header, but doesn't actually point to resolved. We mustn't
		// try to program resolved in that case.
		// https://github.com/tailscale/tailscale/issues/2136
		if err := resolvedIsActuallyResolver(logf, env, dbg, bs); err != nil {
			logf("dns: resolvedIsActuallyResolver error: %v", err)
			dbg("resolved", "not-in-use")
			return "direct", nil
		}
		if err := env.dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
			dbg("nm", "no")
			return "systemd-resolved", nil
		}
		dbg("nm", "yes")
		if err := env.nmIsUsingResolved(); err != nil {
			dbg("nm-resolved", "no")
			return "systemd-resolved", nil
		}
		dbg("nm-resolved", "yes")

		// Version of NetworkManager before 1.26.6 programmed resolved
		// incorrectly, such that NM's settings would always take
		// precedence over other settings set by other resolved
		// clients.
		//
		// If we're dealing with such a version, we have to set our
		// DNS settings through NM to have them take.
		//
		// However, versions 1.26.6 later both fixed the resolved
		// programming issue _and_ started ignoring DNS settings for
		// "unmanaged" interfaces - meaning NM 1.26.6 and later
		// actively ignore DNS configuration we give it. So, for those
		// NM versions, we can and must use resolved directly.
		//
		// Even more fun, even-older versions of NM won't let us set
		// DNS settings if the interface isn't managed by NM, with a
		// hard failure on DBus requests. Empirically, NM 1.22 does
		// this. Based on the versions popular distros shipped, we
		// conservatively decree that only 1.26.0 through 1.26.5 are
		// "safe" to use for our purposes. This roughly matches
		// distros released in the latter half of 2020.
		//
		// In a perfect world, we'd avoid this by replacing
		// configuration out from under NM entirely (e.g. using
		// directManager to overwrite resolv.conf), but in a world
		// where resolved runs, we need to get correct configuration
		// into resolved regardless of what's in resolv.conf (because
		// resolved can also be queried over dbus, or via an NSS
		// module that bypasses /etc/resolv.conf). Given that we must
		// get correct configuration into resolved, we have no choice
		// but to use NM, and accept the loss of IPv6 configuration
		// that comes with it (see
		// https://github.com/tailscale/tailscale/issues/1699,
		// https://github.com/tailscale/tailscale/pull/1945)
		safe, err := env.nmVersionBetween("1.26.0", "1.26.5")
		if err != nil {
			// Failed to figure out NM's version, can't make a correct
			// decision.
			return "", fmt.Errorf("checking NetworkManager version: %v", err)
		}
		if safe {
			dbg("nm-safe", "yes")
			return "network-manager", nil
		}
		dbg("nm-safe", "no")
		return "systemd-resolved", nil
	case "resolvconf":
		dbg("rc", "resolvconf")
		style := env.resolvconfStyle()
		switch style {
		case "":
			dbg("resolvconf", "no")
			return "direct", nil
		case "debian":
			dbg("resolvconf", "debian")
			return "debian-resolvconf", nil
		case "openresolv":
			dbg("resolvconf", "openresolv")
			return "openresolv", nil
		default:
			// Shouldn't happen, that means we updated flavors of
			// resolvconf without updating here.
			dbg("resolvconf", style)
			logf("[unexpected] got unknown flavor of resolvconf %q, falling back to direct manager", env.resolvconfStyle())
			return "direct", nil
		}
	case "NetworkManager":
		dbg("rc", "nm")
		// Sometimes, NetworkManager owns the configuration but points
		// it at systemd-resolved.
		if err := resolvedIsActuallyResolver(logf, env, dbg, bs); err != nil {
			logf("dns: resolvedIsActuallyResolver error: %v", err)
			dbg("resolved", "not-in-use")
			// You'd think we would use newNMManager here. However, as
			// explained in
			// https://github.com/tailscale/tailscale/issues/1699 ,
			// using NetworkManager for DNS configuration carries with
			// it the cost of losing IPv6 configuration on the
			// Tailscale network interface. So, when we can avoid it,
			// we bypass NetworkManager by replacing resolv.conf
			// directly.
			//
			// If you ever try to put NMManager back here, keep in mind
			// that versions >=1.26.6 will ignore DNS configuration
			// anyway, so you still need a fallback path that uses
			// directManager.
			return "direct", nil
		}
		dbg("nm-resolved", "yes")

		// See large comment above for reasons we'd use NM rather than
		// resolved. systemd-resolved is actually in charge of DNS
		// configuration, but in some cases we might need to configure
		// it via NetworkManager. All the logic below is probing for
		// that case: is NetworkManager running? If so, is it one of
		// the versions that requires direct interaction with it?
		if err := env.dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
			dbg("nm", "no")
			return "systemd-resolved", nil
		}
		safe, err := env.nmVersionBetween("1.26.0", "1.26.5")
		if err != nil {
			// Failed to figure out NM's version, can't make a correct
			// decision.
			return "", fmt.Errorf("checking NetworkManager version: %v", err)
		}
		if safe {
			dbg("nm-safe", "yes")
			return "network-manager", nil
		}
		if err := env.nmIsUsingResolved(); err != nil {
			// If systemd-resolved is not running at all, then we don't have any
			// other choice: we take direct control of DNS.
			dbg("nm-resolved", "no")
			return "direct", nil
		}

		health.SetDNSManagerHealth(errors.New("systemd-resolved and NetworkManager are wired together incorrectly; MagicDNS will probably not work. For more info, see https://tailscale.com/s/resolved-nm"))
		dbg("nm-safe", "no")
		return "systemd-resolved", nil
	default:
		dbg("rc", "unknown")
		return "direct", nil
	}
}

// resolvedIsActuallyResolver reports whether the system is using
// systemd-resolved as the resolver. There are two different ways to
// use systemd-resolved:
//   - libnss_resolve, which requires adding `resolve` to the "hosts:"
//     line in /etc/nsswitch.conf
//   - setting the only nameserver configured in `resolv.conf` to
//     systemd-resolved IP (127.0.0.53)
//
// Returns an error if the configuration is something other than
// exclusively systemd-resolved, or nil if the config is only
// systemd-resolved.
func resolvedIsActuallyResolver(logf logger.Logf, env newOSConfigEnv, dbg func(k, v string), bs []byte) error {
	if err := isLibnssResolveUsed(env); err == nil {
		dbg("resolved", "nss")
		return nil
	}

	cfg, err := readResolv(bytes.NewBuffer(bs))
	if err != nil {
		return err
	}
	// We've encountered at least one system where the line
	// "nameserver 127.0.0.53" appears twice, so we look exhaustively
	// through all of them and allow any number of repeated mentions
	// of the systemd-resolved stub IP.
	if len(cfg.Nameservers) == 0 {
		return errors.New("resolv.conf has no nameservers")
	}
	for _, ns := range cfg.Nameservers {
		if ns != netaddr.IPv4(127, 0, 0, 53) {
			return fmt.Errorf("resolv.conf doesn't point to systemd-resolved; points to %v", cfg.Nameservers)
		}
	}
	dbg("resolved", "file")
	return nil
}

// isLibnssResolveUsed reports whether libnss_resolve is used
// for resolving names. Returns nil if it is, and an error otherwise.
func isLibnssResolveUsed(env newOSConfigEnv) error {
	bs, err := env.fs.ReadFile("/etc/nsswitch.conf")
	if err != nil {
		return fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}
	for _, line := range strings.Split(string(bs), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "hosts:" {
			continue
		}
		for _, module := range fields[1:] {
			if module == "dns" {
				return fmt.Errorf("dns with a higher priority than libnss_resolve")
			}
			if module == "resolve" {
				return nil
			}
		}
	}
	return fmt.Errorf("libnss_resolve not used")
}
