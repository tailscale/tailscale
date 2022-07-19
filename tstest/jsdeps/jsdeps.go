// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package jsdeps is a just a list of the packages we import in the
// JavaScript/WASM build, to let us test that our transitive closure of
// dependencies doesn't accidentally grow too large, since binary size
// is more of a concern.
package jsdeps

import (
	_ "bytes"
	_ "context"
	_ "encoding/hex"
	_ "encoding/json"
	_ "fmt"
	_ "log"
	_ "math/rand"
	_ "net"
	_ "strings"
	_ "time"

	_ "golang.org/x/crypto/ssh"
	_ "inet.af/netaddr"
	_ "tailscale.com/control/controlclient"
	_ "tailscale.com/ipn"
	_ "tailscale.com/ipn/ipnserver"
	_ "tailscale.com/net/netns"
	_ "tailscale.com/net/tsdial"
	_ "tailscale.com/safesocket"
	_ "tailscale.com/tailcfg"
	_ "tailscale.com/types/logger"
	_ "tailscale.com/wgengine"
	_ "tailscale.com/wgengine/netstack"
	_ "tailscale.com/words"
)
