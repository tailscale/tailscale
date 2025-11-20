// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build openbsd

package dns

import (
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"tailscale.com/net/dns/resolvconffile"
	"tailscale.com/types/logger"
)

func newResolvdManager(logf logger.Logf, interfaceName string) (*resolvdManager, error) {
	return &resolvdManager{
		logf:   logf,
		ifName: interfaceName,
		fs:     directFS{},
	}, nil
}

// resolvdManager is an OSConfigurator which uses route(1) to teach OpenBSD's
// resolvd(8) about DNS servers.
type resolvdManager struct {
	logf   logger.Logf
	ifName string
	fs     directFS
}

func (m *resolvdManager) SetDNS(config OSConfig) error {
	args := []string{
		"nameserver",
		m.ifName,
	}

	origResolv, err := m.readAndCopy(resolvConf, backupConf, 0644)
	if err != nil {
		return err
	}
	newResolvConf := removeSearchLines(origResolv)

	for _, ns := range config.Nameservers {
		args = append(args, ns.String())
	}

	var newSearch = []string{
		"search",
	}
	for _, s := range config.SearchDomains {
		newSearch = append(newSearch, s.WithoutTrailingDot())
	}

	if len(newSearch) > 1 {
		newResolvConf = append(newResolvConf, []byte(strings.Join(newSearch, " "))...)
		newResolvConf = append(newResolvConf, '\n')
	}

	err = m.fs.WriteFile(resolvConf, newResolvConf, 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("/sbin/route", args...)
	return cmd.Run()
}

func (m *resolvdManager) SupportsSplitDNS() bool {
	return false
}

func (m *resolvdManager) GetBaseConfig() (OSConfig, error) {
	cfg, err := m.readResolvConf()
	if err != nil {
		return OSConfig{}, err
	}

	return cfg, nil
}

func (m *resolvdManager) Close() error {
	// resolvd handles teardown of nameservers so we only need to write back the original
	// config and be done.

	_, err := m.readAndCopy(backupConf, resolvConf, 0644)
	if err != nil {
		return err
	}

	return m.fs.Remove(backupConf)
}

func (m *resolvdManager) readAndCopy(a, b string, mode os.FileMode) ([]byte, error) {
	orig, err := m.fs.ReadFile(a)
	if err != nil {
		return nil, err
	}
	err = m.fs.WriteFile(b, orig, mode)
	if err != nil {
		return nil, err
	}

	return orig, nil
}

func (m resolvdManager) readResolvConf() (config OSConfig, err error) {
	b, err := m.fs.ReadFile(resolvConf)
	if err != nil {
		return OSConfig{}, err
	}

	rconf, err := resolvconffile.Parse(bytes.NewReader(b))
	if err != nil {
		return config, err
	}
	return OSConfig{
		Nameservers:   rconf.Nameservers,
		SearchDomains: rconf.SearchDomains,
	}, nil
}

func removeSearchLines(orig []byte) []byte {
	re := regexp.MustCompile(`(?ms)^search\s+.+$`)
	return re.ReplaceAll(orig, []byte(""))
}
