// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build openbsd
// +build openbsd

package dns

import (
	"os/exec"

	"tailscale.com/types/logger"
)

func newResolvdManager(logf logger.Logf, interfaceName string) (*resolvdManager, error) {
	return &resolvdManager{
		logf:   logf,
		ifName: interfaceName,
	}, nil
}

// resolvdManager is an OSConfigurator which uses route(1) to teach OpenBSD's
// resolvd(8) about DNS servers.
type resolvdManager struct {
	logf   logger.Logf
	ifName string
}

func (m *resolvdManager) SetDNS(config OSConfig) error {
	args := []string{
		"nameserver",
		m.ifName,
	}

	for _, s := range config.Nameservers {
		args = append(args, s.String())
	}

	cmd := exec.Command("/sbin/route", args...)
	return cmd.Run()
}
func (m *resolvdManager) SupportsSplitDNS() bool {
	return false
}

func (m *resolvdManager) GetBaseConfig() (OSConfig, error) {
	return OSConfig{}, ErrGetBaseConfigNotSupported
}

func (m *resolvdManager) Close() error {
	// resolvd handles teardown of everything
	return nil
}
