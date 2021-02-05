// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
	"tailscale.com/types/logger"
)

type windowsManager struct {
	logf    logger.Logf
	luid    winipcfg.LUID
	initerr error
}

func newManager(mconfig ManagerConfig) managerImpl {
	m := windowsManager{
		logf: mconfig.Logf,
	}
	var guid windows.GUID
	guid, m.initerr = windows.GUIDFromString(mconfig.InterfaceName)
	if m.initerr != nil {
		return m
	}
	m.luid, m.initerr = winipcfg.LUIDFromGUID(&guid)
	return m
}

func (m windowsManager) Up(config Config) error {
	if m.initerr != nil {
		return m.initerr
	}

	var ips []net.IP
	for _, ip := range config.Nameservers {
		ips = append(ips, ip.IPAddr().IP)
	}
	err := m.luid.SetDNS(ips)
	if err != nil {
		return err
	}

	dnsSearch := ""
	if len(config.Domains) > 0 {
		dnsSearch = config.Domains[0]
	}
	err = m.luid.SetDNSDomain(dnsSearch)
	if err != nil {
		return nil
	}
	if len(config.Domains) > 1 {
		m.logf("%d DNS search domains were specified, but only one is supported, so the first one (%s) was used.", len(config.Domains), dnsSearch)
	}
	return nil
}

func (m windowsManager) Down() error {
	return m.Up(Config{Nameservers: nil, Domains: nil})
}
