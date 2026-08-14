// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android

package hostinfo

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"tailscale.com/util/lineiter"
	"tailscale.com/version/distro"
)

func init() {
	osVersion = lazyOSVersion.Get
	packageType = packageTypeLinux
	distroName = distroNameLinux
	distroVersion = distroVersionLinux
	distroCodeName = distroCodeNameLinux
	deviceModel = deviceModelLinux
	systemdLogindDesktop = hasLogindDesktop
}

var (
	lazyVersionMeta = &lazyAtomicValue[versionMeta]{f: new(linuxVersionMeta)}
	lazyOSVersion   = &lazyAtomicValue[string]{f: new(osVersionLinux)}
)

type versionMeta struct {
	DistroName     string
	DistroVersion  string
	DistroCodeName string // "jammy", etc (VERSION_CODENAME from /etc/os-release)
}

func distroNameLinux() string {
	return lazyVersionMeta.Get().DistroName
}

func distroVersionLinux() string {
	return lazyVersionMeta.Get().DistroVersion
}

func distroCodeNameLinux() string {
	return lazyVersionMeta.Get().DistroCodeName
}

func deviceModelLinux() string {
	for _, path := range []string{
		// First try the Synology-specific location.
		// Example: "DS916+-j"
		"/proc/sys/kernel/syno_hw_version",

		// Otherwise, try the Devicetree model, usually set on
		// ARM SBCs, etc.
		// Example: "Raspberry Pi 4 Model B Rev 1.2"
		// Example: "WD My Cloud Gen2: Marvell Armada 375"
		"/sys/firmware/devicetree/base/model", // Raspberry Pi 4 Model B Rev 1.2"
	} {
		b, _ := os.ReadFile(path)
		if s := strings.Trim(string(b), "\x00\r\n\t "); s != "" {
			return s
		}
	}
	return ""
}

func getQnapQtsVersion(versionInfo string) string {
	for field := range strings.FieldsSeq(versionInfo) {
		if suffix, ok := strings.CutPrefix(field, "QTSFW_"); ok {
			return suffix
		}
	}
	return ""
}

func osVersionLinux() string {
	var un unix.Utsname
	unix.Uname(&un)
	return unix.ByteSliceToString(un.Release[:])
}

func linuxVersionMeta() (meta versionMeta) {
	dist := distro.Get()
	meta.DistroName = string(dist)

	propFile := "/etc/os-release"
	switch dist {
	case distro.Synology:
		propFile = "/etc.defaults/VERSION"
	case distro.OpenWrt:
		propFile = "/etc/openwrt_release"
	case distro.Unraid:
		propFile = "/etc/unraid-version"
	case distro.WDMyCloud:
		slurp, _ := os.ReadFile("/etc/version")
		meta.DistroVersion = string(bytes.TrimSpace(slurp))
		return
	case distro.QNAP:
		slurp, _ := os.ReadFile("/etc/version_info")
		meta.DistroVersion = getQnapQtsVersion(string(slurp))
		return
	}

	m := map[string]string{}
	for lr := range lineiter.File(propFile) {
		line, err := lr.Value()
		if err != nil {
			break
		}
		before, after, ok := bytes.Cut(line, []byte{'='})
		if !ok {
			continue
		}
		k, v := string(before), strings.Trim(string(after), `"'`)
		m[k] = v
	}

	if v := m["VERSION_CODENAME"]; v != "" {
		meta.DistroCodeName = v
	}
	if v := m["VERSION_ID"]; v != "" {
		meta.DistroVersion = v
	}
	id := m["ID"]
	if id != "" {
		meta.DistroName = id
	}
	switch id {
	case "debian":
		// Debian's VERSION_ID is just like "11". But /etc/debian_version has "11.5" normally.
		// Or "bookworm/sid" on sid/testing.
		slurp, _ := os.ReadFile("/etc/debian_version")
		if v := string(bytes.TrimSpace(slurp)); v != "" {
			if '0' <= v[0] && v[0] <= '9' {
				meta.DistroVersion = v
			} else if meta.DistroCodeName == "" {
				meta.DistroCodeName = v
			}
		}
	case "", "centos": // CentOS 6 has no /etc/os-release, so its id is ""
		if meta.DistroVersion == "" {
			if cr, _ := os.ReadFile("/etc/centos-release"); len(cr) > 0 { // "CentOS release 6.10 (Final)
				meta.DistroVersion = string(bytes.TrimSpace(cr))
			}
		}
	}
	if v := m["PRETTY_NAME"]; v != "" && meta.DistroVersion == "" && !strings.HasSuffix(v, "/sid") {
		meta.DistroVersion = v
	}
	switch dist {
	case distro.Synology:
		meta.DistroVersion = m["productversion"]
	case distro.OpenWrt:
		meta.DistroVersion = m["DISTRIB_RELEASE"]
	case distro.Unraid:
		meta.DistroVersion = m["version"]
	}
	return
}

// linuxBuildTagPackageType is set by packagetype_*.go
// build tag guarded files.
var linuxBuildTagPackageType string

func packageTypeLinux() string {
	if v := linuxBuildTagPackageType; v != "" {
		return v
	}
	// Report whether this is in a snap.
	// See https://snapcraft.io/docs/environment-variables
	// We just look at two somewhat arbitrarily.
	if os.Getenv("SNAP_NAME") != "" && os.Getenv("SNAP") != "" {
		return "snap"
	}
	return ""
}

// hasLogindDesktop calls [systemdLogindFindDesktop] with a 100 millisecond
// timeout.
func hasLogindDesktop() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	runner := &osLogindRunner{ctx: ctx}
	return systemdLogindFindDesktop(runner)
}

// logindConn is the interface for querying systemd-logind session information.
// It exists to be able to swap the backend for testing.
type logindRunner interface {
	// listSessions returns the raw JSON output of
	// "loginctl list-sessions --json=short", which is a json blob containing
	// output like: '[{"session":"8"},{"session":"9"}]'.
	listSessions() ([]byte, error)

	// getSessionType returns the raw output of
	// "loginctl show-session <id> --property=Type", which is a single line of
	// the form "Type=<value>".
	getSessionType(string) (string, error)
}

// osLogindRunner implements [logindRunner] by shelling out to the system logind.
type osLogindRunner struct{ ctx context.Context }

// listSessions implements [logindRunner] using os calls.
func (r *osLogindRunner) listSessions() ([]byte, error) {
	path, err := exec.LookPath("loginctl")
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(r.ctx, path, "list-sessions", "--json=short")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return output, nil
}

// getSessionType implements [logindRunner] using os calls.
func (r *osLogindRunner) getSessionType(session string) (string, error) {
	path, err := exec.LookPath("loginctl")
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(r.ctx,
		path, "show-session", session, "--property=Type", "--value")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// systemdLogindFindDesktop reports whether any active logind session has a
// graphical desktop type (x11, wayland, or mir). On an error or with no types
// matching the list above, it returns false.
func systemdLogindFindDesktop(logind logindRunner) bool {
	sessionJSON, err := logind.listSessions()
	if err != nil {
		return false
	}

	type session struct {
		Session string `json:"session"`
	}

	var sessions []session
	err = json.Unmarshal(sessionJSON, &sessions)
	if err != nil {
		return false
	}

	for _, sess := range sessions {
		typeString, err := logind.getSessionType(sess.Session)
		if err != nil {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(typeString)) {
		case "wayland", "x11", "mir":
			return true
		}
	}

	return false
}
