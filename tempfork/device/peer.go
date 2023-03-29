/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"

	"tailscale.com/types/key"
)

type Peer struct {
	trieEntries list.List

	key key.NodePublic
}

func NewPeer(k key.NodePublic) *Peer {
	return &Peer{
		key: k,
	}
}

func (p *Peer) Key() key.NodePublic {
	return p.key
}
