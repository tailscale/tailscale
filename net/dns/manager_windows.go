// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
	"tailscale.com/types/logger"
)

const (
	ipv4RegBase = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	ipv6RegBase = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
)

type windowsManager struct {
	logf logger.Logf
	guid string
}

func newManager(logf logger.Logf, interfaceName string) managerImpl {
	return windowsManager{
		logf: logf,
		guid: interfaceName,
	}
}

// keyOpenTimeout is how long we wait for a registry key to
// appear. For some reason, registry keys tied to ephemeral interfaces
// can take a long while to appear after interface creation, and we
// can end up racing with that.
const keyOpenTimeout = 20 * time.Second

func setRegistryString(path, name, value string) error {
	key, err := openKeyWait(registry.LOCAL_MACHINE, path, registry.SET_VALUE, keyOpenTimeout)
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

func (m windowsManager) setNameservers(basePath string, nameservers []string) error {
	path := fmt.Sprintf(`%s\Interfaces\%s`, basePath, m.guid)
	value := strings.Join(nameservers, ",")
	return setRegistryString(path, "NameServer", value)
}

func (m windowsManager) setDomains(basePath string, domains []string) error {
	path := fmt.Sprintf(`%s\Interfaces\%s`, basePath, m.guid)
	value := strings.Join(domains, ",")
	return setRegistryString(path, "SearchList", value)
}

func (m windowsManager) Up(config OSConfig) error {
	var ipsv4 []string
	var ipsv6 []string

	for _, ip := range config.Nameservers {
		if ip.Is4() {
			ipsv4 = append(ipsv4, ip.String())
		} else {
			ipsv6 = append(ipsv6, ip.String())
		}
	}

	if err := m.setNameservers(ipv4RegBase, ipsv4); err != nil {
		return err
	}
	if err := m.setDomains(ipv4RegBase, config.Domains); err != nil {
		return err
	}

	if err := m.setNameservers(ipv6RegBase, ipsv6); err != nil {
		return err
	}
	if err := m.setDomains(ipv6RegBase, config.Domains); err != nil {
		return err
	}

	// Force DNS re-registration in Active Directory. What we actually
	// care about is that this command invokes the undocumented hidden
	// function that forces Windows to notice that adapter settings
	// have changed, which makes the DNS settings actually take
	// effect.
	//
	// This command can take a few seconds to run, so run it async, best effort.
	go func() {
		t0 := time.Now()
		m.logf("running ipconfig /registerdns ...")
		cmd := exec.Command("ipconfig", "/registerdns")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		d := time.Since(t0).Round(time.Millisecond)
		if err := cmd.Run(); err != nil {
			m.logf("error running ipconfig /registerdns after %v: %v", d, err)
		} else {
			m.logf("ran ipconfig /registerdns in %v", d)
		}
	}()

	return nil
}

func (m windowsManager) Down() error {
	return m.Up(OSConfig{Nameservers: nil, Domains: nil})
}
