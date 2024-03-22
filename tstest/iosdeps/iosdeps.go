// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package iosdeps is a just a list of the packages we import on iOS, to let us
// test that our transitive closure of dependencies on iOS doesn't accidentally
// grow too large, as we've historically been memory constrained there.
package iosdeps

import (
	_ "bufio"
	_ "bytes"
	_ "context"
	_ "crypto/rand"
	_ "crypto/sha256"
	_ "encoding/json"
	_ "errors"
	_ "fmt"
	_ "io"
	_ "io/fs"
	_ "log"
	_ "math"
	_ "net"
	_ "net/http"
	_ "os"
	_ "os/signal"
	_ "path/filepath"
	_ "runtime"
	_ "runtime/debug"
	_ "strings"
	_ "sync"
	_ "sync/atomic"
	_ "syscall"
	_ "time"
	_ "unsafe"

	_ "github.com/tailscale/wireguard-go/device"
	_ "github.com/tailscale/wireguard-go/tun"
	_ "go4.org/mem"
	_ "golang.org/x/sys/unix"
	_ "tailscale.com/hostinfo"
	_ "tailscale.com/ipn"
	_ "tailscale.com/ipn/ipnlocal"
	_ "tailscale.com/ipn/localapi"
	_ "tailscale.com/logtail"
	_ "tailscale.com/logtail/filch"
	_ "tailscale.com/net/dns"
	_ "tailscale.com/net/netaddr"
	_ "tailscale.com/net/tsdial"
	_ "tailscale.com/net/tstun"
	_ "tailscale.com/paths"
	_ "tailscale.com/types/empty"
	_ "tailscale.com/types/logger"
	_ "tailscale.com/util/clientmetric"
	_ "tailscale.com/util/dnsname"
	_ "tailscale.com/version"
	_ "tailscale.com/wgengine"
	_ "tailscale.com/wgengine/router"
)
