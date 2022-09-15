// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux || (darwin && !ios)
// +build linux darwin,!ios

package ipnlocal

import (
	"bytes"
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

	"github.com/tailscale/golang-x-crypto/ssh"
	"tailscale.com/util/mak"
)

// keyTypes are the SSH key types that we either try to read from the
// system's OpenSSH keys or try to generate for ourselves when not
// running as root.
var keyTypes = []string{"rsa", "ecdsa", "ed25519"}

func (b *LocalBackend) GetSSH_HostKeys() (keys []ssh.Signer, err error) {
	var existing map[string]ssh.Signer
	if os.Geteuid() == 0 {
		existing = b.getSystemSSH_HostKeys()
	}
	return b.getTailscaleSSH_HostKeys(existing)
}

// getTailscaleSSH_HostKeys returns the three (rsa, ecdsa, ed25519) SSH host
// keys, reusing the provided ones in existing if present in the map.
func (b *LocalBackend) getTailscaleSSH_HostKeys(existing map[string]ssh.Signer) (keys []ssh.Signer, err error) {
	var keyDir string // lazily initialized $TAILSCALE_VAR/ssh dir.
	for _, typ := range keyTypes {
		if s, ok := existing[typ]; ok {
			keys = append(keys, s)
			continue
		}
		if keyDir == "" {
			root := b.TailscaleVarRoot()
			if root == "" {
				return nil, errors.New("no var root for ssh keys")
			}
			keyDir = filepath.Join(root, "ssh")
			if err := os.MkdirAll(keyDir, 0700); err != nil {
				return nil, err
			}
		}
		hostKey, err := b.hostKeyFileOrCreate(keyDir, typ)
		if err != nil {
			return nil, fmt.Errorf("error creating SSH host key type %q in %q: %w", typ, keyDir, err)
		}
		signer, err := ssh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing SSH host key type %q from %q: %w", typ, keyDir, err)
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
	var priv any
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

func (b *LocalBackend) getSystemSSH_HostKeys() (ret map[string]ssh.Signer) {
	for _, typ := range keyTypes {
		filename := "/etc/ssh/ssh_host_" + typ + "_key"
		hostKey, err := ioutil.ReadFile(filename)
		if err != nil || len(bytes.TrimSpace(hostKey)) == 0 {
			continue
		}
		signer, err := ssh.ParsePrivateKey(hostKey)
		if err != nil {
			b.logf("warning: error reading host key %s: %v (generating one instead)", filename, err)
			continue
		}
		mak.Set(&ret, typ, signer)
	}
	return ret
}

func (b *LocalBackend) getSSHHostKeyPublicStrings() (ret []string) {
	signers, _ := b.GetSSH_HostKeys()
	for _, signer := range signers {
		ret = append(ret, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	}
	return ret
}
