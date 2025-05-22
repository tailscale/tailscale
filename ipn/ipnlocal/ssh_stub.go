// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android || (!linux && !darwin && !freebsd && !openbsd && !plan9)

package ipnlocal

import (
	"errors"

	"golang.org/x/crypto/ssh"
	"tailscale.com/tailcfg"
)

func (b *LocalBackend) getSSHHostKeyPublicStrings() ([]string, error) {
	return nil, nil
}

func (b *LocalBackend) getSSHUsernames(*tailcfg.C2NSSHUsernamesRequest) (*tailcfg.C2NSSHUsernamesResponse, error) {
	return nil, errors.New("not implemented")
}

func (b *LocalBackend) GetSSH_HostKeys() (keys []ssh.Signer, err error) {
	return nil, errors.New("not implemented")
}
