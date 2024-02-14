// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux || freebsd || openbsd

package dns

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

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
	bs, err := exec.Command("resolvconf", "-i").CombinedOutput()
	if err != nil {
		return OSConfig{}, err
	}

	// Remove the "tailscale" snippet from the list.
	args := []string{"-l"}
	for _, f := range strings.Split(strings.TrimSpace(string(bs)), " ") {
		if f == "tailscale" {
			continue
		}
		args = append(args, f)
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
	var buf bytes.Buffer
	cmd := exec.Command("resolvconf", args...)
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		m.logCmdErr(cmd, err)
		return OSConfig{}, err
	}
	return readResolv(&buf)
}

func (m openresolvManager) Close() error {
	return m.deleteTailscaleConfig()
}
