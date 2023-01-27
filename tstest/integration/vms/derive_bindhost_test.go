// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vms

import (
	"io"
	"net/netip"
	"runtime"
	"testing"

	"tailscale.com/net/interfaces"
)

func deriveBindhost(t *testing.T) string {
	t.Helper()

	ifName, err := interfaces.DefaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}

	var ret string
	err = interfaces.ForeachInterfaceAddress(func(i interfaces.Interface, prefix netip.Prefix) {
		if ret != "" || i.Name != ifName {
			return
		}
		ret = prefix.Addr().String()
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
	if runtime.GOOS != "linux" {
		t.Skip("requires GOOS=linux")
	}
	t.Log(deriveBindhost(t))
}

type nopWriteCloser struct {
	io.Writer
}

func (nwc nopWriteCloser) Close() error { return nil }
