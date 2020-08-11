// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
)

const (
	ipv4RegBase = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	ipv6RegBase = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
	tsRegBase   = `SOFTWARE\Tailscale IPN`
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

func setRegistryString(path, name, value string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer key.Close()

	err = key.SetStringValue(name, value)
	if err != nil {
		return fmt.Errorf("setting %s[%s]: %w", path, name, err)
	}
	return nil
}

func getRegistryString(path, name string) (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
	if err != nil {
		return "", fmt.Errorf("opening %s: %w", path, err)
	}
	defer key.Close()

	value, _, err := key.GetStringValue(name)
	if err != nil {
		return "", fmt.Errorf("getting %s[%s]: %w", path, name, err)
	}
	return value, nil
}

func (m windowsManager) setNameservers(basePath string, nameservers []string) error {
	path := fmt.Sprintf(`%s\Interfaces\%s`, basePath, m.guid)
	value := strings.Join(nameservers, ",")
	return setRegistryString(path, "NameServer", value)
}

func (m windowsManager) setDomains(path string, oldDomains, newDomains []string) error {
	// We reimplement setRegistryString to ensure that we hold the key for the whole operation.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ|registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer key.Close()

	searchList, _, err := key.GetStringValue("SearchList")
	if err != nil && err != registry.ErrNotExist {
		return fmt.Errorf("getting %s[SearchList]: %w", path, err)
	}
	currentDomains := strings.Split(searchList, ",")

	var domainsToSet []string
	for _, domain := range currentDomains {
		inOld, inNew := false, false

		// The number of domains should be small,
		// so this is probaly faster than constructing a map.
		for _, oldDomain := range oldDomains {
			if domain == oldDomain {
				inOld = true
			}
		}
		for _, newDomain := range newDomains {
			if domain == newDomain {
				inNew = true
			}
		}

		if !inNew && !inOld {
			domainsToSet = append(domainsToSet, domain)
		}
	}
	domainsToSet = append(domainsToSet, newDomains...)

	searchList = strings.Join(domainsToSet, ",")
	if err := key.SetStringValue("SearchList", searchList); err != nil {
		return fmt.Errorf("setting %s[SearchList]: %w", path, err)
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

	lastSearchList, err := getRegistryString(tsRegBase, "SearchList")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	lastDomains := strings.Split(lastSearchList, ",")

	if err := m.setNameservers(ipv4RegBase, ipsv4); err != nil {
		return err
	}
	if err := m.setDomains(ipv4RegBase, lastDomains, config.Domains); err != nil {
		return err
	}

	if err := m.setNameservers(ipv6RegBase, ipsv6); err != nil {
		return err
	}
	if err := m.setDomains(ipv6RegBase, lastDomains, config.Domains); err != nil {
		return err
	}

	newSearchList := strings.Join(config.Domains, ",")
	if err := setRegistryString(tsRegBase, "SearchList", newSearchList); err != nil {
		return err
	}

	return nil
}

func (m windowsManager) Down() error {
	return m.Up(Config{Nameservers: nil, Domains: nil})
}
