// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android

package ipnlocal

import (
	"errors"
	"net"

	"tailscale.com/client/tailscale"
)

type webServer struct{}

func (b *LocalBackend) SetWebLocalClient(lc *tailscale.LocalClient) {}

func (b *LocalBackend) WebInit() error {
	return errors.New("not implemented")
}

func (b *LocalBackend) WebShutdown() {}

func (b *LocalBackend) handleWebClientConn(c net.Conn) error {
	return errors.New("not implemented")
}
