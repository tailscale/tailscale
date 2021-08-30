// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/godbus/dbus/v5"
	"inet.af/netaddr"
	"tailscale.com/types/logger"
	"tailscale.com/util/cmpver"
)

type kv struct {
	k, v string
}

func (kv kv) String() string {
	return fmt.Sprintf("%s=%s", kv.k, kv.v)
}

func NewOSConfigurator(logf logger.Logf, interfaceName string) (ret OSConfigurator, err error) {
	return newOSConfigurator(logf, interfaceName, newOSConfigEnv{
		fs:                         directFS{},
		resolvOwner:                resolvOwner,
		resolvedIsActuallyResolver: resolvedIsActuallyResolver,
		dbusPing:                   dbusPing,
		nmIsUsingResolved:          nmIsUsingResolved,
		nmVersionBetween:           nmVersionBetween,
		getResolvConfVersion:       getResolvConfVersion,
	})
}

// newOSConfigEnv are the funcs newOSConfigurator needs, pulled out for testing.
type newOSConfigEnv struct {
	fs                         wholeFileFS
	resolvOwner                func(resolvConfContents []byte) string
	resolvedIsActuallyResolver func(wholeFileFS) error
	dbusPing                   func(string, string) error
	nmIsUsingResolved          func() error
	nmVersionBetween           func(v1, v2 string) (safe bool, err error)
	getResolvConfVersion       func() ([]byte, error)
}

func newOSConfigurator(logf logger.Logf, interfaceName string, env newOSConfigEnv) (ret OSConfigurator, err error) {
	var debug []kv
	dbg := func(k, v string) {
		debug = append(debug, kv{k, v})
	}
	defer func() {
		if ret != nil {
			dbg("ret", fmt.Sprintf("%T", ret))
		}
		logf("dns: %v", debug)
	}()

	bs, err := env.fs.ReadFile(resolvConf)
	if os.IsNotExist(err) {
		dbg("rc", "missing")
		return newDirectManager(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	switch env.resolvOwner(bs) {
	case "systemd-resolved":
		dbg("rc", "resolved")
		// Some systems, for reasons known only to them, have a
		// resolv.conf that has the word "systemd-resolved" in its
		// header, but doesn't actually point to resolved. We mustn't
		// try to program resolved in that case.
		// https://github.com/tailscale/tailscale/issues/2136
		if err := env.resolvedIsActuallyResolver(env.fs); err != nil {
			dbg("resolved", "not-in-use")
			return newDirectManagerOnFS(env.fs), nil
		}
		if err := env.dbusPing("org.freedesktop.resolve1", "/org/freedesktop/resolve1"); err != nil {
			dbg("resolved", "no")
			return newDirectManagerOnFS(env.fs), nil
		}
		if err := env.dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
			dbg("nm", "no")
			return newResolvedManager(logf, interfaceName)
		}
		dbg("nm", "yes")
		if err := env.nmIsUsingResolved(); err != nil {
			dbg("nm-resolved", "no")
			return newResolvedManager(logf, interfaceName)
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
		safe, err := nmVersionBetween("1.26.0", "1.26.5")
		if err != nil {
			// Failed to figure out NM's version, can't make a correct
			// decision.
			return nil, fmt.Errorf("checking NetworkManager version: %v", err)
		}
		if safe {
			dbg("nm-safe", "yes")
			return newNMManager(interfaceName)
		}
		dbg("nm-safe", "no")
		return newResolvedManager(logf, interfaceName)
	case "resolvconf":
		dbg("rc", "resolvconf")
		if _, err := exec.LookPath("resolvconf"); err != nil {
			dbg("resolvconf", "no")
			return newDirectManagerOnFS(env.fs), nil
		}
		dbg("resolvconf", "yes")
		return newResolvconfManager(logf, env.getResolvConfVersion)
	case "NetworkManager":
		// You'd think we would use newNMManager somewhere in
		// here. However, as explained in
		// https://github.com/tailscale/tailscale/issues/1699 , using
		// NetworkManager for DNS configuration carries with it the
		// cost of losing IPv6 configuration on the Tailscale network
		// interface. So, when we can avoid it, we bypass
		// NetworkManager by replacing resolv.conf directly.
		//
		// If you ever try to put NMManager back here, keep in mind
		// that versions >=1.26.6 will ignore DNS configuration
		// anyway, so you still need a fallback path that uses
		// directManager.
		dbg("rc", "nm")
		return newDirectManagerOnFS(env.fs), nil
	default:
		dbg("rc", "unknown")
		return newDirectManagerOnFS(env.fs), nil
	}
}

func nmVersionBetween(first, last string) (bool, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return false, err
	}

	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager"))
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.Version")
	if err != nil {
		return false, err
	}

	version, ok := v.Value().(string)
	if !ok {
		return false, fmt.Errorf("unexpected type %T for NM version", v.Value())
	}

	outside := cmpver.Compare(version, first) < 0 || cmpver.Compare(version, last) > 0
	return !outside, nil
}

func nmIsUsingResolved() error {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"))
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.DnsManager.Mode")
	if err != nil {
		return fmt.Errorf("getting NM mode: %w", err)
	}
	mode, ok := v.Value().(string)
	if !ok {
		return fmt.Errorf("unexpected type %T for NM DNS mode", v.Value())
	}
	if mode != "systemd-resolved" {
		return errors.New("NetworkManager is not using systemd-resolved for DNS")
	}
	return nil
}

func resolvedIsActuallyResolver(fs wholeFileFS) error {
	cfg, err := newDirectManagerOnFS(fs).readResolvConf()
	if err != nil {
		return err
	}
	if len(cfg.Nameservers) != 1 || cfg.Nameservers[0] != netaddr.IPv4(127, 0, 0, 53) {
		return errors.New("resolv.conf doesn't point to systemd-resolved")
	}
	return nil
}

func dbusPing(name, objectPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	obj := conn.Object(name, dbus.ObjectPath(objectPath))
	call := obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	return call.Err
}
