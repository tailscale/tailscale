// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || freebsd || openbsd

package dns

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"

	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

// openresolvManager manages DNS configuration using the openresolv
// implementation of the `resolvconf` program.
type openresolvManager struct {
	logf logger.Logf
}

func newOpenresolvManager(logf logger.Logf) (openresolvManager, error) {
	return openresolvManager{logf}, nil
}

func (m openresolvManager) logCmdErr(cmd *exec.Cmd, err error) {
	if err == nil {
		return
	}

	commandStr := fmt.Sprintf("path=%q args=%q", cmd.Path, cmd.Args)
	exerr, ok := err.(*exec.ExitError)
	if !ok {
		m.logf("error running command %s: %v", commandStr, err)
		return
	}

	m.logf("error running command %s stderr=%q exitCode=%d: %v", commandStr, exerr.Stderr, exerr.ExitCode(), err)
}

// openresolvNoSnippetsExitCode is the exit status resolvconf returns when a
// requested config snippet does not exist. Asking for all snippets when none
// are registered returns this status too, because openresolv treats the empty
// result as a missing snippet rather than as an empty list.
const openresolvNoSnippetsExitCode = 2

// readSnippets runs resolvconf with the given arguments and returns its stdout.
// An exit status of openresolvNoSnippetsExitCode is not an error: it returns no
// output and a nil error. Other failures are logged and returned.
//
// Callers must pass either "-i" with no arguments or "-l" with explicit snippet
// names. Only those forms produce empty stdout alongside
// openresolvNoSnippetsExitCode; "-i" with snippet names prints the ones that do
// exist and still exits 2, so its output would be silently dropped.
//
// Stderr is excluded from the returned bytes so that diagnostics like "No
// resolv.conf for key foo" are never parsed as snippet names or resolv.conf
// lines. logCmdErr still logs stderr when a command fails.
func (m openresolvManager) readSnippets(args ...string) ([]byte, error) {
	cmd := exec.Command("resolvconf", args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := errors.AsType[*exec.ExitError](err); ok && ee.ExitCode() == openresolvNoSnippetsExitCode {
			m.logf("[v1] resolvconf %q found no matching config snippets", args)
			return nil, nil
		}
		m.logCmdErr(cmd, err)
		return nil, err
	}
	return out, nil
}

func (m openresolvManager) deleteTailscaleConfig() error {
	cmd := exec.Command("resolvconf", "-f", "-d", "tailscale")
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.logCmdErr(cmd, err)
		return fmt.Errorf("running %s: %s", cmd, out)
	}
	return nil
}

func (m openresolvManager) SetDNS(config OSConfig) error {
	if config.IsZero() {
		return m.deleteTailscaleConfig()
	}

	var stdin bytes.Buffer
	writeResolvConf(&stdin, config.Nameservers, config.SearchDomains)

	cmd := exec.Command("resolvconf", "-m", "0", "-x", "-a", "tailscale")
	cmd.Stdin = &stdin
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.logCmdErr(cmd, err)
		return fmt.Errorf("running %s: %s", cmd, out)
	}
	return nil
}

func (m openresolvManager) SupportsSplitDNS() bool {
	return false
}

func (m openresolvManager) GetBaseConfig() (OSConfig, error) {
	// List the names of all config snippets openresolv is aware
	// of. Snippets get listed in priority order (most to least),
	// which we'll exploit later.
	bs, err := m.readSnippets("-i")
	if err != nil {
		return OSConfig{}, err
	}

	others := slices.DeleteFunc(strings.Fields(string(bs)), func(f string) bool {
		return f == "tailscale"
	})
	if len(others) == 0 {
		// There are no other snippets, so there is no base config to read.
		// Returning early is required, not merely an optimization: a
		// "resolvconf -l" with no snippet names lists every snippet,
		// including Tailscale's own, which would make quad-100 its own
		// upstream. See tailscale/tailscale#20825.
		return OSConfig{}, nil
	}

	// List all resolvconf snippets except our own, and parse that as
	// a resolv.conf. This effectively generates a blended config of
	// "everyone except tailscale", which is what would be in use if
	// tailscale hadn't set exclusive mode.
	//
	// Note that this is not _entirely_ true. To be perfectly correct,
	// we should be looking for other interfaces marked exclusive that
	// predated tailscale, and stick to only those. However, in
	// practice, openresolv uses are generally quite limited, and boil
	// down to 1-2 DHCP leases, for which the correct outcome is a
	// blended config like the one we produce here.
	out, err := m.readSnippets(append([]string{"-l"}, others...)...)
	if err != nil {
		return OSConfig{}, err
	}
	cfg, err := readResolv(bytes.NewReader(out))
	if err != nil {
		return OSConfig{}, err
	}

	// Forwarding to the Tailscale service IPs would make quad-100 send
	// queries to itself, in an infinite loop, so drop them if another
	// snippet names them. See tailscale/tailscale#7816.
	var removed bool
	cfg.Nameservers = slices.DeleteFunc(cfg.Nameservers, func(ip netip.Addr) bool {
		if ip == tsaddr.TailscaleServiceIP() || ip == tsaddr.TailscaleServiceIPv6() {
			removed = true
			return true
		}
		return false
	})
	if removed {
		m.logf("[v1] dropped Tailscale service IP from openresolv base config")
	}
	return cfg, nil
}

func (m openresolvManager) Close() error {
	return m.deleteTailscaleConfig()
}
