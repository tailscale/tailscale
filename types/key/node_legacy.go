// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package key

import (
	"go4.org/mem"
)

// NodeKey is the legacy form of NodePublic.
// See #3206 for removal effort.
type NodeKey [32]byte

func (k NodeKey) ShortString() string          { return k.AsNodePublic().ShortString() }
func (k NodeKey) String() string               { return k.AsNodePublic().String() }
func (k NodeKey) MarshalText() ([]byte, error) { return k.AsNodePublic().MarshalText() }
func (k NodeKey) AsNodePublic() NodePublic     { return NodePublicFromRaw32(mem.B(k[:])) }
func (k NodeKey) IsZero() bool                 { return k == NodeKey{} }

func (k *NodeKey) UnmarshalText(text []byte) error {
	var nk NodePublic
	if err := nk.UnmarshalText(text); err != nil {
		return err
	}
	*k = nk.AsNodeKey()
	return nil
}
