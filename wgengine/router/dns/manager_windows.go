// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"fmt"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
)

type windowsManager struct {
	logf logger.Logf
	guid string
}

func newManager(mconfig ManagerConfig) managerImpl {
	return windowsManager{
		logf: mconfig.Logf,
		guid: tun.WintunGUID,
	}
}

func setRegistry(path, nameservers, domains string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer key.Close()

	err = key.SetStringValue("NameServer", nameservers)
	if err != nil {
		return fmt.Errorf("setting %s/NameServer: %w", path, err)
	}

	err = key.SetStringValue("Domain", domains)
	if err != nil {
		return fmt.Errorf("setting %s/Domain: %w", path, err)
	}

	return nil
}

func (m windowsManager) Up(config Config) error {
	var ipsv4 []string
	var ipsv6 []string
	for _, ip := range config.Nameservers {
		if ip.Is4() {
			ipsv4 = append(ipsv4, ip.String())
		} else {
			ipsv6 = append(ipsv6, ip.String())
		}
	}
	nsv4 := strings.Join(ipsv4, ",")
	nsv6 := strings.Join(ipsv6, ",")

	var domains string
	if len(config.Domains) > 0 {
		if len(config.Domains) > 1 {
			m.logf("only a single search domain is supported")
		}
		domains = config.Domains[0]
	}

	v4Path := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + m.guid
	if err := setRegistry(v4Path, nsv4, domains); err != nil {
		return err
	}
	v6Path := `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\` + m.guid
	if err := setRegistry(v6Path, nsv6, domains); err != nil {
		return err
	}

	return nil
}

func (m windowsManager) Down() error {
	return m.Up(Config{Nameservers: nil, Domains: nil})
}
