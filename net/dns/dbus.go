// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && !ts_omit_dbus

package dns

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

func init() {
	optDBusPing.Set(dbusPing)
	optDBusReadString.Set(dbusReadString)
}

func dbusPing(name, objectPath string) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	obj := conn.Object(name, dbus.ObjectPath(objectPath))
	call := obj.CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0)
	return call.Err
}

// dbusReadString reads a string property from the provided name and object
// path. property must be in "interface.member" notation.
func dbusReadString(name, objectPath, iface, member string) (string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		// DBus probably not running.
		return "", err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	obj := conn.Object(name, dbus.ObjectPath(objectPath))

	var result dbus.Variant
	err = obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, member).Store(&result)
	if err != nil {
		return "", err
	}

	if s, ok := result.Value().(string); ok {
		return s, nil
	}
	return result.String(), nil
}
