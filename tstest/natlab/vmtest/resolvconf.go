// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"bytes"
	"embed"
	"fmt"
	"regexp"
)

// These paths are where openresolv gets installed in the guest. openresolv's
// build bakes them into its scripts with sed substitutions (see its Makefile),
// so they have to agree with openresolvSubst below.
const (
	// openresolvSbinDir must be on the default PATH, because net/dns finds
	// resolvconf with exec.LookPath (see resolvconfStyle in
	// net/dns/resolvconf.go).
	openresolvSbinDir = "/sbin"

	// openresolvSysconfDir is where resolvconf looks for resolvconf.conf.
	openresolvSysconfDir = "/etc"

	// openresolvLibexecDir holds the subscriber scripts resolvconf runs after
	// a snippet is added or removed.
	openresolvLibexecDir = "/usr/libexec/resolvconf"

	// openresolvVarDir is resolvconf's runtime state directory. Its "keys"
	// subdirectory is where registered config snippets live.
	openresolvVarDir = "/run/resolvconf"

	// openresolvKeyDir is created empty by provisioning; see [DNSOpenresolv].
	openresolvKeyDir = openresolvVarDir + "/keys"
)

// openresolvSrc holds the vendored openresolv sources. See
// testdata/openresolv/README.md for their provenance.
//
//go:embed testdata/openresolv/*.in
var openresolvSrc embed.FS

// openresolvFile is one file natlab installs into the guest to provide
// openresolv.
type openresolvFile struct {
	guestPath string // absolute path to install to in the guest
	srcName   string // vendored source to substitute, relative to testdata/openresolv
	inline    string // literal contents, for files with no upstream source
	mode      string // octal permissions for cloud-init to apply
}

// openresolvInstall is the subset of openresolv's own files this mode installs.
//
// Upstream ships further subscriber scripts, for dnsmasq and unbound among
// others. Leaving those out is safe, because each of openresolv's subscriber
// loops skips a script that is not present. libc is the one script that has to
// be installed, because it writes resolv.conf.
var openresolvInstall = []openresolvFile{
	{
		guestPath: openresolvSbinDir + "/resolvconf",
		srcName:   "resolvconf.in",
		mode:      "0755",
	},
	{
		// resolvconf sources this rather than exec'ing it if it isn't
		// executable, so it needs no exec bit.
		guestPath: openresolvLibexecDir + "/libc",
		srcName:   "libc.in",
		mode:      "0644",
	},
	{
		// Upstream's own default, which its "make install" installs too.
		// What matters here is that the file exists at all: without it,
		// resolvconf switches to the original Debian layout if
		// /etc/resolvconf happens to be a directory, which is not what this
		// mode tests.
		guestPath: openresolvSysconfDir + "/resolvconf.conf",
		inline:    "resolv_conf=/etc/resolv.conf\n",
		mode:      "0644",
	},
}

// openresolvSubst is openresolv's build-time substitution table. Its Makefile
// seds these placeholders out of the .in files; natlab does the same, so the
// test needs no configure-and-make step.
//
// RCDIR, RESTARTCMD and STATUSARG are empty, as they are in an unconfigured
// upstream build. resolvconf's detect_init() then picks a restart command at
// runtime, which is systemctl on these guests. That command restarts the libc
// service only when it is already active. Here the libc service is nscd, which
// these guests do not run.
var openresolvSubst = map[string]string{
	"@SBINDIR@":    openresolvSbinDir,
	"@SYSCONFDIR@": openresolvSysconfDir,
	"@LIBEXECDIR@": openresolvLibexecDir,
	"@VARDIR@":     openresolvVarDir,
	"@RCDIR@":      "",
	"@RESTARTCMD@": "",
	"@STATUSARG@":  "",
}

var openresolvPlaceholderRx = regexp.MustCompile(`@[A-Z_]+@`)

// substOpenresolv applies openresolvSubst to b, and fails if any placeholder
// survives. An openresolv release that adds one would otherwise install a
// shell script containing a literal "@FOO@", which fails in the guest in some
// far less obvious way.
func substOpenresolv(name string, b []byte) ([]byte, error) {
	for k, v := range openresolvSubst {
		b = bytes.ReplaceAll(b, []byte(k), []byte(v))
	}
	if m := openresolvPlaceholderRx.Find(b); m != nil {
		return nil, fmt.Errorf("%s: unsubstituted placeholder %q; openresolvSubst needs updating for the vendored openresolv", name, m)
	}
	return b, nil
}

// buildOpenresolv returns the files to install in the guest, in the order
// openresolvInstall lists them.
func buildOpenresolv() ([]cloudInitFile, error) {
	out := make([]cloudInitFile, 0, len(openresolvInstall))
	for _, f := range openresolvInstall {
		content := []byte(f.inline)
		if f.srcName != "" {
			b, err := openresolvSrc.ReadFile("testdata/openresolv/" + f.srcName)
			if err != nil {
				return nil, err
			}
			if b, err = substOpenresolv(f.srcName, b); err != nil {
				return nil, err
			}
			content = b
		}
		out = append(out, cloudInitFile{
			path:    f.guestPath,
			content: content,
			mode:    f.mode,
		})
	}
	return out, nil
}
