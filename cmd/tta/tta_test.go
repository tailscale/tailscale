// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"net"
	"reflect"
	"testing"
	"time"
)

func TestDriverDialer(t *testing.T) {
	d := driverDialer()
	if d.Control != nil || d.ControlContext == nil {
		t.Fatal("driver dialer must use ControlContext exclusively")
	}
	if reflect.ValueOf(d.ControlContext).Pointer() != reflect.ValueOf(bypassControlFunc).Pointer() {
		t.Error("driver dialer did not install the platform bypass hook")
	}
	want := net.KeepAliveConfig{Enable: true, Idle: 5 * time.Second, Interval: 5 * time.Second, Count: 3}
	if d.KeepAliveConfig != want {
		t.Errorf("keepalive = %+v; want %+v", d.KeepAliveConfig, want)
	}
}
