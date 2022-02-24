// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ios || (!linux && !darwin)

package ipnlocal

func (b *LocalBackend) getSSHHostKeyPublicStrings() []string {
	return nil
}
