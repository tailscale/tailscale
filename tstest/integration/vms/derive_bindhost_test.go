// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package vms

import (
	"io"
	"testing"

	"inet.af/netaddr"
	"tailscale.com/net/interfaces"
)

func deriveBindhost(t *testing.T) string {
	t.Helper()

	ifName, err := interfaces.DefaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}

	var ret string
	err = interfaces.ForeachInterfaceAddress(func(i interfaces.Interface, prefix netaddr.IPPrefix) {
		if ret != "" || i.Name != ifName {
			return
		}
		ret = prefix.IP().String()
	})
	if ret != "" {
		return ret
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("can't find a bindhost")
	return "unreachable"
}

func TestDeriveBindhost(t *testing.T) {
	t.Log(deriveBindhost(t))
}

type nopWriteCloser struct {
	io.Writer
}

func (nwc nopWriteCloser) Close() error { return nil }
