// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"tailscale.com/feature/featuretags"
	"tailscale.com/tstest/deptest"
)

func TestOmitSSH(t *testing.T) {
	const msg = "unexpected with ts_omit_ssh"
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_ssh,ts_include_cli",
		BadDeps: map[string]string{
			"golang.org/x/crypto/ssh":              msg,
			"tailscale.com/ssh/tailssh":            msg,
			"tailscale.com/sessionrecording":       msg,
			"github.com/anmitsu/go-shlex":          msg,
			"github.com/creack/pty":                msg,
			"github.com/kr/fs":                     msg,
			"github.com/pkg/sftp":                  msg,
			"github.com/u-root/u-root/pkg/termios": msg,
			"tempfork/gliderlabs/ssh":              msg,
		},
	}.Check(t)
}

func TestOmitSyspolicy(t *testing.T) {
	const msg = "unexpected syspolicy usage with ts_omit_syspolicy"
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_syspolicy,ts_include_cli",
		BadDeps: map[string]string{
			"tailscale.com/util/syspolicy":         msg,
			"tailscale.com/util/syspolicy/setting": msg,
			"tailscale.com/util/syspolicy/rsop":    msg,
		},
	}.Check(t)
}

func TestOmitLocalClient(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_webclient,ts_omit_relayserver,ts_omit_oauthkey,ts_omit_acme",
		BadDeps: map[string]string{
			"tailscale.com/client/local": "unexpected",
		},
	}.Check(t)
}

// Test that we can build a binary without reflect.MethodByName.
// See https://github.com/tailscale/tailscale/issues/17063
func TestOmitReflectThings(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_include_cli,ts_omit_systray,ts_omit_debugeventbus,ts_omit_webclient",
		BadDeps: map[string]string{
			"text/template": "unexpected text/template usage",
			"html/template": "unexpected text/template usage",
		},
		OnDep: func(dep string) {
			if strings.Contains(dep, "systray") {
				t.Errorf("unexpected systray dep %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitDrive(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_drive,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "driveimpl") {
				t.Errorf("unexpected dep with ts_omit_drive: %q", dep)
			}
			if strings.Contains(dep, "webdav") {
				t.Errorf("unexpected dep with ts_omit_drive: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitPortmapper(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_portmapper,ts_include_cli,ts_omit_debugportmapper",
		OnDep: func(dep string) {
			if dep == "tailscale.com/net/portmapper" {
				t.Errorf("unexpected dep with ts_omit_portmapper: %q", dep)
				return
			}
			if strings.Contains(dep, "goupnp") || strings.Contains(dep, "/soap") ||
				strings.Contains(dep, "internetgateway2") {
				t.Errorf("unexpected dep with ts_omit_portmapper: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitACME(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_acme,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "/acme") {
				t.Errorf("unexpected dep with ts_omit_acme: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitCaptivePortal(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_captiveportal,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "captive") {
				t.Errorf("unexpected dep with ts_omit_captiveportal: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitOAuthKey(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_oauthkey,ts_include_cli",
		OnDep: func(dep string) {
			if strings.HasPrefix(dep, "golang.org/x/oauth2") {
				t.Errorf("unexpected dep with ts_omit_oauthkey: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitOutboundProxy(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_outboundproxy,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "socks5") || strings.Contains(dep, "proxymux") {
				t.Errorf("unexpected dep with ts_omit_outboundproxy: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitDBus(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_networkmanager,ts_omit_dbus,ts_omit_resolved,ts_omit_systray,ts_omit_ssh,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "dbus") {
				t.Errorf("unexpected DBus dep: %q", dep)
			}
		},
	}.Check(t)
}

func TestNetstack(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_gro,ts_omit_netstack,ts_omit_outboundproxy,ts_omit_serve,ts_omit_ssh,ts_omit_webclient,ts_omit_tap",
		OnDep: func(dep string) {
			if strings.Contains(dep, "gvisor") {
				t.Errorf("unexpected gvisor dep: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitPortlist(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_portlist,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "portlist") {
				t.Errorf("unexpected dep: %q", dep)
			}
		},
	}.Check(t)
}

func TestOmitGRO(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_gro,ts_include_cli",
		BadDeps: map[string]string{
			"gvisor.dev/gvisor/pkg/tcpip/stack/gro": "unexpected dep with ts_omit_gro",
		},
	}.Check(t)
}

func TestOmitUseProxy(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   "ts_omit_useproxy,ts_include_cli",
		OnDep: func(dep string) {
			if strings.Contains(dep, "tshttproxy") {
				t.Errorf("unexpected dep: %q", dep)
			}
		},
	}.Check(t)
}

func minTags() string {
	var tags []string
	for _, f := range slices.Sorted(maps.Keys(featuretags.Features)) {
		if f.IsOmittable() {
			tags = append(tags, f.OmitTag())
		}
	}
	return strings.Join(tags, ",")
}

func TestMinTailscaledNoCLI(t *testing.T) {
	badSubstrs := []string{
		"cbor",
		"regexp",
		"golang.org/x/net/proxy",
		"internal/socks",
		"github.com/tailscale/peercred",
		"tailscale.com/types/netlogtype",
	}
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   minTags(),
		OnDep: func(dep string) {
			for _, bad := range badSubstrs {
				if strings.Contains(dep, bad) {
					t.Errorf("unexpected dep: %q", dep)
				}
			}
		},
	}.Check(t)
}

func TestMinTailscaledWithCLI(t *testing.T) {
	badSubstrs := []string{
		"cbor",
		"hujson",
		"pprof",
		"multierr", // https://github.com/tailscale/tailscale/pull/17379
	}
	deptest.DepChecker{
		GOOS:   "linux",
		GOARCH: "amd64",
		Tags:   minTags() + ",ts_include_cli",
		OnDep: func(dep string) {
			for _, bad := range badSubstrs {
				if strings.Contains(dep, bad) {
					t.Errorf("unexpected dep: %q", dep)
				}
			}
		},
		BadDeps: map[string]string{
			"golang.org/x/net/http2": "unexpected x/net/http2 dep; tailscale/tailscale#17305",
		},
	}.Check(t)
}
