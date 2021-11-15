// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"errors"
	"io/fs"
	"os"
	"strings"
	"testing"

	"tailscale.com/tstest"
	"tailscale.com/util/cmpver"
)

func TestLinuxDNSMode(t *testing.T) {
	tests := []struct {
		name    string
		env     newOSConfigEnv
		wantLog string
		want    string
	}{
		{
			name:    "no_obvious_resolv.conf_owner",
			env:     env(resolvDotConf("nameserver 10.0.0.1")),
			wantLog: "dns: [rc=unknown ret=direct]",
			want:    "direct",
		},
		{
			name: "network_manager",
			env: env(
				resolvDotConf(
					"# Managed by NetworkManager",
					"nameserver 10.0.0.1")),
			wantLog: "dns: [rc=nm resolved=not-in-use ret=direct]",
			want:    "direct",
		},
		{
			name:    "resolvconf_but_no_resolvconf_binary",
			env:     env(resolvDotConf("# Managed by resolvconf", "nameserver 10.0.0.1")),
			wantLog: "dns: [rc=resolvconf resolvconf=no ret=direct]",
			want:    "direct",
		},
		{
			name: "debian_resolvconf",
			env: env(
				resolvDotConf("# Managed by resolvconf", "nameserver 10.0.0.1"),
				resolvconf("debian")),
			wantLog: "dns: [rc=resolvconf resolvconf=debian ret=debian-resolvconf]",
			want:    "debian-resolvconf",
		},
		{
			name: "openresolv",
			env: env(
				resolvDotConf("# Managed by resolvconf", "nameserver 10.0.0.1"),
				resolvconf("openresolv")),
			wantLog: "dns: [rc=resolvconf resolvconf=openresolv ret=openresolv]",
			want:    "openresolv",
		},
		{
			name: "unknown_resolvconf_flavor",
			env: env(
				resolvDotConf("# Managed by resolvconf", "nameserver 10.0.0.1"),
				resolvconf("daves-discount-resolvconf")),
			wantLog: "[unexpected] got unknown flavor of resolvconf \"daves-discount-resolvconf\", falling back to direct manager\ndns: [rc=resolvconf resolvconf=daves-discount-resolvconf ret=direct]",
			want:    "direct",
		},
		{
			name:    "resolved_not_running",
			env:     env(resolvDotConf("# Managed by systemd-resolved", "nameserver 127.0.0.53")),
			wantLog: "dns: [rc=resolved resolved=no ret=direct]",
			want:    "direct",
		},
		{
			name: "resolved_alone",
			env: env(
				resolvDotConf("# Managed by systemd-resolved", "nameserver 127.0.0.53"),
				resolvedRunning()),
			wantLog: "dns: [rc=resolved nm=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
		{
			name: "resolved_and_networkmanager_not_using_resolved",
			env: env(
				resolvDotConf("# Managed by systemd-resolved", "nameserver 127.0.0.53"),
				resolvedRunning(),
				nmRunning("1.2.3", false)),
			wantLog: "dns: [rc=resolved nm=yes nm-resolved=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
		{
			name: "resolved_and_mid_2020_networkmanager",
			env: env(
				resolvDotConf("# Managed by systemd-resolved", "nameserver 127.0.0.53"),
				resolvedRunning(),
				nmRunning("1.26.2", true)),
			wantLog: "dns: [rc=resolved nm=yes nm-resolved=yes nm-safe=yes ret=network-manager]",
			want:    "network-manager",
		},
		{
			name: "resolved_and_2021_networkmanager",
			env: env(
				resolvDotConf("# Managed by systemd-resolved", "nameserver 127.0.0.53"),
				resolvedRunning(),
				nmRunning("1.27.0", true)),
			wantLog: "dns: [rc=resolved nm=yes nm-resolved=yes nm-safe=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
		{
			name: "resolved_and_ancient_networkmanager",
			env: env(
				resolvDotConf("# Managed by systemd-resolved", "nameserver 127.0.0.53"),
				resolvedRunning(),
				nmRunning("1.22.0", true)),
			wantLog: "dns: [rc=resolved nm=yes nm-resolved=yes nm-safe=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
		// Regression tests for extreme corner cases below.
		{
			// One user reported a configuration whose comment string
			// alleged that it was managed by systemd-resolved, but it
			// was actually a completely static config file pointing
			// elsewhere.
			name:    "allegedly_resolved_but_not_in_resolv.conf",
			env:     env(resolvDotConf("# Managed by systemd-resolved", "nameserver 10.0.0.1")),
			wantLog: "dns: [rc=resolved resolved=not-in-use ret=direct]",
			want:    "direct",
		},
		{
			// We used to incorrectly decide that resolved wasn't in
			// charge when handed this (admittedly weird and bugged)
			// resolv.conf.
			name: "resolved_with_duplicates_in_resolv.conf",
			env: env(
				resolvDotConf(
					"# Managed by systemd-resolved",
					"nameserver 127.0.0.53",
					"nameserver 127.0.0.53"),
				resolvedRunning()),
			wantLog: "dns: [rc=resolved nm=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
		{
			// More than one user has had resolvconf write a config that points to
			// systemd-resolved. We're better off using systemd-resolved.
			// regression test for https://github.com/tailscale/tailscale/issues/3026
			name: "allegedly_resolvconf_but_actually_systemd-resolved",
			env: env(resolvDotConf(
				"# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)",
				"#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN",
				"# 127.0.0.53 is the systemd-resolved stub resolver.",
				"# run \"systemd-resolve --status\" to see details about the actual nameservers.",
				"nameserver 127.0.0.53"),
				resolvedRunning()),
			wantLog: "dns: [rc=resolved nm=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
		{
			// More than one user has had resolvconf write a config that points to
			// systemd-resolved. We're better off using systemd-resolved.
			// ...but what if systemd-resolved isn't running?
			// regression test for https://github.com/tailscale/tailscale/issues/3026
			name: "allegedly_resolvconf_but_actually_systemd-resolved_but_not_really",
			env: env(resolvDotConf(
				"# Dynamic resolv.conf(5) file for glibc resolver(3) generated by resolvconf(8)",
				"#     DO NOT EDIT THIS FILE BY HAND -- YOUR CHANGES WILL BE OVERWRITTEN",
				"# 127.0.0.53 is the systemd-resolved stub resolver.",
				"# run \"systemd-resolve --status\" to see details about the actual nameservers.",
				"nameserver 127.0.0.53")),
			wantLog: "dns: [rc=resolved resolved=no ret=direct]",
			want:    "direct",
		},
		{
			// regression test for https://github.com/tailscale/tailscale/issues/3304
			name: "networkmanager_but_pointing_at_systemd-resolved",
			env: env(resolvDotConf(
				"# Generated by NetworkManager",
				"nameserver 127.0.0.53",
				"options edns0 trust-ad"),
				resolvedRunning(),
				nmRunning("1.32.12", true)),
			wantLog: "dns: [rc=nm nm-resolved=yes nm-safe=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
		{
			// regression test for https://github.com/tailscale/tailscale/issues/3304
			name: "networkmanager_but_pointing_at_systemd-resolved_but_no_resolved",
			env: env(resolvDotConf(
				"# Generated by NetworkManager",
				"nameserver 127.0.0.53",
				"options edns0 trust-ad"),
				nmRunning("1.32.12", true)),
			wantLog: "dns: [rc=nm nm-resolved=yes resolved=no ret=direct]",
			want:    "direct",
		},
		{
			// regression test for https://github.com/tailscale/tailscale/issues/3304
			name: "networkmanager_but_pointing_at_systemd-resolved_and_safe_nm",
			env: env(resolvDotConf(
				"# Generated by NetworkManager",
				"nameserver 127.0.0.53",
				"options edns0 trust-ad"),
				resolvedRunning(),
				nmRunning("1.26.3", true)),
			wantLog: "dns: [rc=nm nm-resolved=yes nm-safe=yes ret=network-manager]",
			want:    "network-manager",
		},
		{
			// regression test for https://github.com/tailscale/tailscale/issues/3304
			name: "networkmanager_but_pointing_at_systemd-resolved_and_no_networkmanager",
			env: env(resolvDotConf(
				"# Generated by NetworkManager",
				"nameserver 127.0.0.53",
				"options edns0 trust-ad"),
				resolvedRunning()),
			wantLog: "dns: [rc=nm nm-resolved=yes nm=no ret=systemd-resolved]",
			want:    "systemd-resolved",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf tstest.MemLogger
			got, err := dnsMode(logBuf.Logf, tt.env)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %s; want %s", got, tt.want)
			}
			if got := strings.TrimSpace(logBuf.String()); got != tt.wantLog {
				t.Errorf("log output mismatch:\n got: %q\nwant: %q\n", got, tt.wantLog)
			}
		})
	}
}

type memFS map[string]interface{} // full path => string for regular files

func (m memFS) Stat(name string) (isRegular bool, err error) {
	v, ok := m[name]
	if !ok {
		return false, fs.ErrNotExist
	}
	if _, ok := v.(string); ok {
		return true, nil
	}
	return false, nil
}

func (m memFS) Rename(oldName, newName string) error { panic("TODO") }
func (m memFS) Remove(name string) error             { panic("TODO") }
func (m memFS) ReadFile(name string) ([]byte, error) {
	v, ok := m[name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	if s, ok := v.(string); ok {
		return []byte(s), nil
	}
	panic("TODO")
}

func (m memFS) Truncate(name string) error {
	v, ok := m[name]
	if !ok {
		return fs.ErrNotExist
	}
	if s, ok := v.(string); ok {
		m[name] = s[:0]
	}

	return nil
}

func (m memFS) WriteFile(name string, contents []byte, perm os.FileMode) error {
	m[name] = string(contents)
	return nil
}

type envBuilder struct {
	fs              memFS
	dbus            []struct{ name, path string }
	nmUsingResolved bool
	nmVersion       string
	resolvconfStyle string
}

type envOption interface {
	apply(*envBuilder)
}

type envOpt func(*envBuilder)

func (e envOpt) apply(b *envBuilder) {
	e(b)
}

func env(opts ...envOption) newOSConfigEnv {
	b := &envBuilder{
		fs: memFS{},
	}
	for _, opt := range opts {
		opt.apply(b)
	}

	return newOSConfigEnv{
		fs: b.fs,
		dbusPing: func(name, path string) error {
			for _, svc := range b.dbus {
				if svc.name == name && svc.path == path {
					return nil
				}
			}
			return errors.New("dbus service not found")
		},
		nmIsUsingResolved: func() error {
			if !b.nmUsingResolved {
				return errors.New("networkmanager not using resolved")
			}
			return nil
		},
		nmVersionBetween: func(first, last string) (bool, error) {
			outside := cmpver.Compare(b.nmVersion, first) < 0 || cmpver.Compare(b.nmVersion, last) > 0
			return !outside, nil
		},
		resolvconfStyle: func() string { return b.resolvconfStyle },
	}
}

func resolvDotConf(ss ...string) envOption {
	return envOpt(func(b *envBuilder) {
		b.fs["/etc/resolv.conf"] = strings.Join(ss, "\n")
	})
}

func resolvedRunning() envOption {
	return envOpt(func(b *envBuilder) {
		b.dbus = append(b.dbus, struct{ name, path string }{"org.freedesktop.resolve1", "/org/freedesktop/resolve1"})
	})
}

func nmRunning(version string, usingResolved bool) envOption {
	return envOpt(func(b *envBuilder) {
		b.nmUsingResolved = usingResolved
		b.nmVersion = version
		b.dbus = append(b.dbus, struct{ name, path string }{"org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"})
	})
}

func resolvconf(s string) envOption {
	return envOpt(func(b *envBuilder) {
		b.resolvconfStyle = s
	})
}
