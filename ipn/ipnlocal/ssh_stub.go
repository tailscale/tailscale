// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ios || (!linux && !darwin && !freebsd)

package ipnlocal

import (
	"errors"

	"tailscale.com/tailcfg"
)

func (b *LocalBackend) getSSHHostKeyPublicStrings() []string {
	return nil
}

func (b *LocalBackend) getSSHUsernames(*tailcfg.C2NSSHUsernamesRequest) (*tailcfg.C2NSSHUsernamesResponse, error) {
	return nil, errors.New("not implemented")
}
