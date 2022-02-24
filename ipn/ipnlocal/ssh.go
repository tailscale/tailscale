// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

package ipnlocal

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"tailscale.com/envknob"
)

var useHostKeys = envknob.Bool("TS_USE_SYSTEM_SSH_HOST_KEYS")

// keyTypes are the SSH key types that we either try to read from the
// system's OpenSSH keys or try to generate for ourselves when not
// running as root.
var keyTypes = []string{"rsa", "ecdsa", "ed25519"}

func (b *LocalBackend) GetSSH_HostKeys() (keys []ssh.Signer, err error) {
	if os.Geteuid() == 0 {
		keys, err = b.getSystemSSH_HostKeys()
		if err != nil || len(keys) > 0 {
			return keys, err
		}
		// Otherwise, perhaps they don't have OpenSSH etc installed.
		// Generate our own keys...
	}
	return b.getTailscaleSSH_HostKeys()
}

func (b *LocalBackend) getTailscaleSSH_HostKeys() (keys []ssh.Signer, err error) {
	root := b.TailscaleVarRoot()
	if root == "" {
		return nil, errors.New("no var root for ssh keys")
	}
	keyDir := filepath.Join(root, "ssh")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, err
	}
	for _, typ := range keyTypes {
		hostKey, err := b.hostKeyFileOrCreate(keyDir, typ)
		if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, err
		}
		keys = append(keys, signer)
	}
	return keys, nil
}

var keyGenMu sync.Mutex

func (b *LocalBackend) hostKeyFileOrCreate(keyDir, typ string) ([]byte, error) {
	keyGenMu.Lock()
	defer keyGenMu.Unlock()

	path := filepath.Join(keyDir, "ssh_host_"+typ+"_key")
	v, err := ioutil.ReadFile(path)
	if err == nil {
		return v, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	var priv interface{}
	switch typ {
	default:
		return nil, fmt.Errorf("unsupported key type %q", typ)
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		// curve is arbitrary. We pick whatever will at
		// least pacify clients as the actual encryption
		// doesn't matter: it's all over WireGuard anyway.
		curve := elliptic.P256()
		priv, err = ecdsa.GenerateKey(curve, rand.Reader)
	case "rsa":
		// keySize is arbitrary. We pick whatever will at
		// least pacify clients as the actual encryption
		// doesn't matter: it's all over WireGuard anyway.
		const keySize = 2048
		priv, err = rsa.GenerateKey(rand.Reader, keySize)
	}
	if err != nil {
		return nil, err
	}
	mk, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemGen := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mk})
	err = os.WriteFile(path, pemGen, 0700)
	return pemGen, err
}

func (b *LocalBackend) getSystemSSH_HostKeys() (ret []ssh.Signer, err error) {
	// TODO(bradfitz): cache this?
	for _, typ := range keyTypes {
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
	return ret, nil
}

func (b *LocalBackend) getSSHHostKeyPublicStrings() (ret []string) {
	signers, _ := b.GetSSH_HostKeys()
	for _, signer := range signers {
		ret = append(ret, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	}
	return ret
}
