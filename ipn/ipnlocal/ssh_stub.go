// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || (!linux && !darwin && !freebsd && !openbsd)

package ipnlocal

import (
	"errors"

	"tailscale.com/tailcfg"
)

func (b *LocalBackend) getSSHHostKeyPublicStrings() ([]string, error) {
	return nil, nil
}

func (b *LocalBackend) getSSHUsernames(*tailcfg.C2NSSHUsernamesRequest) (*tailcfg.C2NSSHUsernamesResponse, error) {
	return nil, errors.New("not implemented")
}
