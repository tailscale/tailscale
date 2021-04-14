// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"tailscale.com/types/logger"
)

func NewOSConfigurator(logf logger.Logf, interfaceName string) (OSConfigurator, error) {
	bs, err := ioutil.ReadFile("/etc/resolv.conf")
	if os.IsNotExist(err) {
		return newDirectManager()
	}

	switch resolvOwner(bs) {
	case "systemd-resolved":
		if err := dbusPing("org.freedesktop.resolve1", "/org/freedesktop/resolve1"); err != nil {
			return newDirectManager()
		}
		if err := dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
			return newResolvedManager(logf)
		}
		if err := nmIsUsingResolved(); err != nil {
			return newResolvedManager(logf)
		}
		return newNMManager(interfaceName)
	case "resolvconf":
		if err := resolvconfSourceIsNM(bs); err == nil {
			if err := dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
				return newNMManager(interfaceName)
			}
		}
		if _, err := exec.LookPath("resolvconf"); err != nil {
			return newDirectManager()
		}
		return newResolvconfManager(logf)
	case "NetworkManager":
		if err := dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
			return newDirectManager()
		}
		return newNMManager(interfaceName)
	default:
		return newDirectManager()
	}
}

func resolvconfSourceIsNM(resolvDotConf []byte) error {
	b := bytes.NewBuffer(resolvDotConf)
	cfg, err := readResolv(b)
	if err != nil {
		return fmt.Errorf("parsing /etc/resolv.conf: %w", err)
	}

	var (
		paths = []string{
			"/etc/resolvconf/run/interface/NetworkManager",
			"/run/resolvconf/interface/NetworkManager",
			"/var/run/resolvconf/interface/NetworkManager",
			"/run/resolvconf/interfaces/NetworkManager",
			"/var/run/resolvconf/interfaces/NetworkManager",
		}
		nmCfg OSConfig
		found bool
	)
	for _, path := range paths {
		nmCfg, err = readResolvFile(path)
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		found = true
		break
	}
	if !found {
		return errors.New("NetworkManager resolvconf snippet not found")
	}

	if !nmCfg.Equal(cfg) {
		return errors.New("NetworkManager config not applied by resolvconf")
	}

	return nil
}

func nmIsUsingResolved() error {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	nm := conn.Object("org.freedesktop.NetworkManager", dbus.ObjectPath("/org/freedesktop/NetworkManager/DnsManager"))
	v, err := nm.GetProperty("org.freedesktop.NetworkManager.DnsManager.Mode")
	if err != nil {
		return fmt.Errorf("getting NM mode: %w", err)
	}
	mode, ok := v.Value().(string)
	if !ok {
		return fmt.Errorf("unexpected type %T for NM DNS mode", v.Value())
	}
	if mode != "systemd-resolved" {
		return errors.New("NetworkManager is not using systemd-resolved for DNS")
	}
	return nil
}

func dbusPing(name, objectPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	obj := conn.Object(name, dbus.ObjectPath(objectPath))
	call := obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	return call.Err
}

// resolvOwner returns the apparent owner of the resolv.conf
// configuration in bs - one of "resolvconf", "systemd-resolved" or
// "NetworkManager", or "" if no known owner was found.
func resolvOwner(bs []byte) string {
	b := bytes.NewBuffer(bs)
	for {
		line, err := b.ReadString('\n')
		if err != nil {
			return ""
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line[0] != '#' {
			// First non-empty, non-comment line. Assume the owner
			// isn't hiding further down.
			return ""
		}

		if strings.Contains(line, "systemd-resolved") {
			return "systemd-resolved"
		} else if strings.Contains(line, "NetworkManager") {
			return "NetworkManager"
		} else if strings.Contains(line, "resolvconf") {
			return "resolvconf"
		}
	}
}
