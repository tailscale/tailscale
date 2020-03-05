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
	derpHostOfIndex = map[int]string{} // node ID index (fake port number) -> hostname
	derpIndexOfHost = map[string]int{} // derpHostOfIndex reversed
	derpNodeID      []int
)

const (
	derpUSNY = 1
	derpUSSF = 2
	derpSG   = 3
	derpDE   = 4
)

func init() {
	addDerper(derpUSNY, "derp1.tailscale.com")
	addDerper(derpUSSF, "derp2.tailscale.com")
	addDerper(derpSG, "derp3.tailscale.com")
	addDerper(derpDE, "derp4.tailscale.com")
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
	derpNodeID = append(derpNodeID, i)
}

// derpHost returns the hostname of a DERP server index (a fake port
// number used with derpMagicIP).
func derpHost(i int) string {
	if h, ok := derpHostOfIndex[i]; ok {
		return h
	}
	if 1 <= i && i <= 64<<10 {
		return fmt.Sprintf("derp%v.tailscale.com", i)
	}
	return ""
}
