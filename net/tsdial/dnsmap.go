// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// canonMapKey canonicalizes its input s to be a MagicDNS lookup key:
// lowercase with no trailing dot.
func canonMapKey(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// errUnresolved is a sentinel error returned when a hostname is not
// resolvable via MagicDNS.
var errUnresolved = errors.New("address well formed but not resolved")

func splitHostPort(addr string) (host string, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port16, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in address %q", addr)
	}
	return host, uint16(port16), nil
}
