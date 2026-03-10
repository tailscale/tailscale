// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_customdisco

package magicsock

import (
	"tailscale.com/disco"
	"tailscale.com/types/key"
)

type customDiscoRegistry struct{}

// CustomDiscoMessage is a stub when custom disco support is omitted.
type CustomDiscoMessage struct{}

func (c *Conn) AddCustomDiscoMessage(*CustomDiscoMessage)        {}
func (c *Conn) customDiscoAcceptsUnknownPeers() bool             { return false }
func (c *Conn) customDiscoParseHook(disco.MessageType, uint8, []byte) (disco.Message, error) {
	return nil, nil
}
func (customDiscoRegistry) handleMessage(disco.MessageType, disco.Message, key.DiscoPublic, key.NodePublic) {
}
func (c *Conn) SendCustomDiscoOverDERP(key.DiscoPublic, key.NodePublic, int, disco.Message) (bool, error) {
	return false, nil
}
