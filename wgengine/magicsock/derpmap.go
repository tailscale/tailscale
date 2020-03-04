// Copyright 2019 Tailscale & AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package magicsock

import (
	"fmt"
	"net"
)

// DerpMagicIP is a fake WireGuard endpoint IP address that means
// to use DERP. When used, the port number of the WireGuard endpoint
// is the DERP server number to use.
//
// Mnemonic: 3.3.40 are numbers above the keys D, E, R, P.
const DerpMagicIP = "127.3.3.40"

var derpMagicIP = net.ParseIP(DerpMagicIP).To4()

var (
	derpHostOfIndex = map[int]string{} // index (fake port number) -> hostname
	derpIndexOfHost = map[string]int{} // derpHostOfIndex reversed
)

const (
	derpNYC = 1
	derpSF  = 2
)

func init() {
	addDerper(derpNYC, "derp.tailscale.com")
	addDerper(derpSF, "derp2.tailscale.com")
}

func addDerper(i int, host string) {
	if other, dup := derpHostOfIndex[i]; dup {
		panic(fmt.Sprintf("duplicate DERP index %v (host %q and %q)", i, other, host))
	}
	if other, dup := derpIndexOfHost[host]; dup {
		panic(fmt.Sprintf("duplicate DERP host %q (index %v and %v)", host, other, i))
	}
	derpHostOfIndex[i] = host
	derpIndexOfHost[host] = i
}

// derpHost returns the hostname of a DERP server index (a fake port
// number used with derpMagicIP). It always returns a non-empty string.
func derpHost(i int) string {
	if h, ok := derpHostOfIndex[i]; ok {
		return h
	}
	if 1 <= i && i <= 64<<10 {
		return fmt.Sprintf("derp%v.tailscale.com", i)
	}
	return "derp.tailscale.com"
}
