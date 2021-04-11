// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// resolvconfIsOpenresolv reports whether the `resolvconf` binary on
// the system is the openresolv implementation.
func resolvconfIsOpenresolv() bool {
	bs, err := exec.Command("resolvconf", "--version").CombinedOutput()
	if err != nil {
		// Either resolvconf isn't installed, or it's not openresolv.
		return false
	}

	return bytes.Contains(bs, []byte("openresolv "))
}

// openresolvManager manages DNS configuration using the openresolv
// implementation of the `resolvconf` program.
type openresolvManager struct{}

func newOpenresolvManager() openresolvManager {
	return openresolvManager{}
}

func (m openresolvManager) SetDNS(config OSConfig) error {
	var stdin bytes.Buffer
	writeResolvConf(&stdin, config.Nameservers, config.SearchDomains)

	cmd := exec.Command("resolvconf", "-m", "0", "-x", "-a", "tailscale")
	cmd.Stdin = &stdin
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s: %s", cmd, out)
	}
	return nil
}

func (m openresolvManager) SupportsSplitDNS() bool {
	return false
}

func (m openresolvManager) GetBaseConfig() (OSConfig, error) {
	bs, err := exec.Command("resolvconf", "-i").CombinedOutput()
	if err != nil {
		return OSConfig{}, err
	}

	args := []string{"-l"}
	for _, f := range strings.Split(strings.TrimSpace(string(bs)), " ") {
		if f == "tailscale" {
			continue
		}
		args = append(args, f)
	}

	var buf bytes.Buffer
	cmd := exec.Command("resolvconf", args...)
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return OSConfig{}, err
	}
	return readResolv(&buf)
}

func (m openresolvManager) Close() error {
	cmd := exec.Command("resolvconf", "-f", "-d", "tailscale")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("running %s: %s", cmd, out)
	}
	return nil
}
