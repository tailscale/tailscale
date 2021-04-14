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
	"time"

	"github.com/godbus/dbus/v5"
	"tailscale.com/types/logger"
)

type kv struct {
	k, v string
}

func (kv kv) String() string {
	return fmt.Sprintf("%s=%s", kv.k, kv.v)
}

func NewOSConfigurator(logf logger.Logf, interfaceName string) (ret OSConfigurator, err error) {
	var debug []kv
	dbg := func(k, v string) {
		debug = append(debug, kv{k, v})
	}
	defer func() {
		if ret != nil {
			dbg("ret", fmt.Sprintf("%T", ret))
		}
		logf("dns: %v", debug)
	}()

	bs, err := ioutil.ReadFile("/etc/resolv.conf")
	if os.IsNotExist(err) {
		dbg("rc", "missing")
		return newDirectManager()
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	switch resolvOwner(bs) {
	case "systemd-resolved":
		dbg("rc", "resolved")
		if err := dbusPing("org.freedesktop.resolve1", "/org/freedesktop/resolve1"); err != nil {
			dbg("resolved", "no")
			return newDirectManager()
		}
		if err := dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
			dbg("nm", "no")
			return newResolvedManager(logf)
		}
		dbg("nm", "yes")
		if err := nmIsUsingResolved(); err != nil {
			dbg("nm-resolved", "no")
			return newResolvedManager(logf)
		}
		dbg("nm-resolved", "yes")
		return newNMManager(interfaceName)
	case "resolvconf":
		dbg("rc", "resolvconf")
		if err := resolvconfSourceIsNM(bs); err == nil {
			dbg("src-is-nm", "yes")
			if err := dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err == nil {
				dbg("nm", "yes")
				return newNMManager(interfaceName)
			}
			dbg("nm", "no")
		}
		dbg("src-is-nm", "no")
		if _, err := exec.LookPath("resolvconf"); err != nil {
			dbg("resolvconf", "no")
			return newDirectManager()
		}
		dbg("resolvconf", "yes")
		return newResolvconfManager(logf)
	case "NetworkManager":
		dbg("rc", "nm")
		if err := dbusPing("org.freedesktop.NetworkManager", "/org/freedesktop/NetworkManager/DnsManager"); err != nil {
			dbg("nm", "no")
			return newDirectManager()
		}
		dbg("nm", "yes")
		return newNMManager(interfaceName)
	default:
		dbg("rc", "unknown")
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
