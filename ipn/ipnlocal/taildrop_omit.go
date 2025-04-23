// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_taildrop

package ipnlocal

import "tailscale.com/ipn"

type taildrop_Manager = struct{}

func (b *LocalBackend) newTaildropManager(fileRoot string, putMode ipn.PutMode) *taildrop_Manager {
	return nil
}
