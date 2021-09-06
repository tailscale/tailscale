// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build openbsd
// +build openbsd

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"tailscale.com/types/logger"
	"tailscale.com/util/dnsname"
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

	newResolvConf = append(newResolvConf, []byte(strings.Join(newSearch, " "))...)

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

	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// resolvd manages "nameserver" lines, we only need to handle
		// "search".
		if strings.HasPrefix(line, "search") {
			domain := strings.TrimPrefix(line, "search")
			domain = strings.TrimSpace(domain)
			fqdn, err := dnsname.ToFQDN(domain)
			if err != nil {
				return OSConfig{}, fmt.Errorf("parsing search domains %q: %w", line, err)
			}
			config.SearchDomains = append(config.SearchDomains, fqdn)
			continue
		}
	}

	return config, nil
}

func removeSearchLines(orig []byte) []byte {
	re := regexp.MustCompile(`(?m)^search\s+.+$`)
	return re.ReplaceAll(orig, []byte(""))
}
