/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package winipcfg

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func runNetsh(cmds []string) error {
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	cmd := exec.Command(filepath.Join(system32, "netsh.exe"))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("runNetsh stdin pipe - %w", err)
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, strings.Join(append(cmds, "exit\r\n"), "\r\n"))
	}()
	output, err := cmd.CombinedOutput()
	// Horrible kludges, sorry.
	cleaned := bytes.ReplaceAll(output, []byte{'\r', '\n'}, []byte{'\n'})
	cleaned = bytes.ReplaceAll(cleaned, []byte("netsh>"), []byte{})
	cleaned = bytes.ReplaceAll(cleaned, []byte("There are no Domain Name Servers (DNS) configured on this computer."), []byte{})
	cleaned = bytes.TrimSpace(cleaned)
	if len(cleaned) != 0 && err == nil {
		return fmt.Errorf("netsh: %#q", string(cleaned))
	} else if err != nil {
		return fmt.Errorf("netsh: %v: %#q", err, string(cleaned))
	}
	return nil
}

const (
	netshCmdTemplateFlush4 = "interface ipv4 set dnsservers name=%d source=static address=none validate=no register=both"
	netshCmdTemplateFlush6 = "interface ipv6 set dnsservers name=%d source=static address=none validate=no register=both"
	netshCmdTemplateAdd4   = "interface ipv4 add dnsservers name=%d address=%s validate=no"
	netshCmdTemplateAdd6   = "interface ipv6 add dnsservers name=%d address=%s validate=no"
)

func (luid LUID) fallbackSetDNSForFamily(family AddressFamily, dnses []net.IP) error {
	var templateFlush string
	if family == windows.AF_INET {
		templateFlush = netshCmdTemplateFlush4
	} else if family == windows.AF_INET6 {
		templateFlush = netshCmdTemplateFlush6
	}

	cmds := make([]string, 0, 1+len(dnses))
	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	cmds = append(cmds, fmt.Sprintf(templateFlush, ipif.InterfaceIndex))
	for i := 0; i < len(dnses); i++ {
		if v4 := dnses[i].To4(); v4 != nil && family == windows.AF_INET {
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd4, ipif.InterfaceIndex, v4.String()))
		} else if v6 := dnses[i].To16(); v4 == nil && v6 != nil && family == windows.AF_INET6 {
			cmds = append(cmds, fmt.Sprintf(netshCmdTemplateAdd6, ipif.InterfaceIndex, v6.String()))
		}
	}
	return runNetsh(cmds)
}

func (luid LUID) fallbackSetDNSDomain(domain string) error {
	guid, err := luid.GUID()
	if err != nil {
		return fmt.Errorf("Error converting luid to guid: %w", err)
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Adapters\\%v", guid), registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("Error opening adapter-specific TCP/IP network registry key: %w", err)
	}
	paths, _, err := key.GetStringsValue("IpConfig")
	key.Close()
	if err != nil {
		return fmt.Errorf("Error reading IpConfig registry key: %w", err)
	}
	if len(paths) == 0 {
		return errors.New("No TCP/IP interfaces found on adapter")
	}
	key, err = registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\%s", paths[0]), registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("Unable to open TCP/IP network registry key: %w", err)
	}
	err = key.SetStringValue("Domain", domain)
	key.Close()
	return err
}
