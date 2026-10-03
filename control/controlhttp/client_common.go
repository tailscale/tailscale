// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlhttp

import (
	"strings"

	"tailscale.com/control/controlbase"
)

// ClientConn is a Tailscale control client as returned by the Dialer.
//
// It's effectively just a *controlbase.Conn (which it embeds) with
// optional metadata.
type ClientConn struct {
	// Conn is the noise connection.
	*controlbase.Conn
}

// Appends server base path to the left, the same way as
// `/base + /endpoint`.
func appendServerBasePath(serverPath string, urlPath string) string {
	serverPath = strings.TrimSuffix(serverPath, "/")
	serverPath = strings.TrimPrefix(serverPath, "/")

	if serverPath == "" {
		return urlPath
	}

	urlPath = strings.TrimSuffix(urlPath, "/")
	urlPath = strings.TrimPrefix(urlPath, "/")

	return "/" + serverPath + "/" + urlPath
}
