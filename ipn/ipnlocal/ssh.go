// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package ipnlocal

import (
	"errors"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
	"tailscale.com/envknob"
)

var useHostKeys = envknob.Bool("TS_USE_SYSTEM_SSH_HOST_KEYS")

func (b *LocalBackend) GetSSHHostKeys() ([]ssh.Signer, error) {
	// TODO(bradfitz): generate host keys, at least as needed if
	// an existing SSH server didn't put them on disk. But also
	// because people may want tailscale-specific ones. For now be
	// lazy and reuse the host ones.
	return b.getSystemSSHHostKeys()
}

func (b *LocalBackend) getSystemSSHHostKeys() (ret []ssh.Signer, err error) {
	for _, typ := range []string{"rsa", "ecdsa", "ed25519"} {
		hostKey, err := ioutil.ReadFile("/etc/ssh/ssh_host_" + typ + "_key")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, err
		}
		ret = append(ret, signer)
	}
	if len(ret) == 0 {
		return nil, errors.New("no system SSH host keys found")
	}
	return ret, nil
}
