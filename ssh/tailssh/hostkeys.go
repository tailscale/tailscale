// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || plan9

package tailssh

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
	"os"
	"path/filepath"
	"strings"
	"sync"

	gossh "golang.org/x/crypto/ssh"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
)

// keyTypes are the SSH key types that we either try to read from the
// system's OpenSSH keys or try to generate for ourselves when not
// running as root.
var keyTypes = []string{"rsa", "ecdsa", "ed25519"}

// getHostKeys returns the SSH host keys, using system keys when running as root
// and generating Tailscale-specific keys as needed.
func getHostKeys(varRoot string, logf logger.Logf) ([]gossh.Signer, error) {
	var existing map[string]gossh.Signer
	if os.Geteuid() == 0 {
		existing = getSystemHostKeys(logf)
	}
	return getTailscaleHostKeys(varRoot, existing)
}

// getHostKeyPublicStrings returns the SSH host key public key strings.
func getHostKeyPublicStrings(varRoot string, logf logger.Logf) ([]string, error) {
	signers, err := getHostKeys(varRoot, logf)
	if err != nil {
		return nil, err
	}
	var keyStrings []string
	for _, signer := range signers {
		keyStrings = append(keyStrings, strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey()))))
	}
	return keyStrings, nil
}

// getTailscaleHostKeys returns the three (rsa, ecdsa, ed25519) SSH host
// keys, reusing the provided ones in existing if present in the map.
func getTailscaleHostKeys(varRoot string, existing map[string]gossh.Signer) (keys []gossh.Signer, err error) {
	var keyDir string // lazily initialized $TAILSCALE_VAR/ssh dir.
	for _, typ := range keyTypes {
		if s, ok := existing[typ]; ok {
			keys = append(keys, s)
			continue
		}
		if keyDir == "" {
			if varRoot == "" {
				return nil, errors.New("no var root for ssh keys")
			}
			keyDir = filepath.Join(varRoot, "ssh")
			if err := os.MkdirAll(keyDir, 0700); err != nil {
				return nil, err
			}
		}
		hostKey, err := hostKeyFileOrCreate(keyDir, typ)
		if err != nil {
			return nil, fmt.Errorf("error creating SSH host key type %q in %q: %w", typ, keyDir, err)
		}
		signer, err := gossh.ParsePrivateKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("error parsing SSH host key type %q from %q: %w", typ, keyDir, err)
		}
		keys = append(keys, signer)
	}
	return keys, nil
}

// keyGenMu protects concurrent generation of host keys with
// [hostKeyFileOrCreate], making sure two callers don't try to concurrently find
// a missing key and generate it at the same time, returning different keys to
// their callers.
//
// Technically we actually want to have a mutex per directory (the keyDir
// passed), but that's overkill for how rarely keys are loaded or generated.
var keyGenMu sync.Mutex

func hostKeyFileOrCreate(keyDir, typ string) ([]byte, error) {
	keyGenMu.Lock()
	defer keyGenMu.Unlock()

	path := filepath.Join(keyDir, "ssh_host_"+typ+"_key")
	v, err := os.ReadFile(path)
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

func getSystemHostKeys(logf logger.Logf) (ret map[string]gossh.Signer) {
	for _, typ := range keyTypes {
		filename := "/etc/ssh/ssh_host_" + typ + "_key"
		hostKey, err := os.ReadFile(filename)
		if err != nil || len(bytes.TrimSpace(hostKey)) == 0 {
			continue
		}
		signer, err := gossh.ParsePrivateKey(hostKey)
		if err != nil {
			logf("warning: error reading host key %s: %v (generating one instead)", filename, err)
			continue
		}
		mak.Set(&ret, typ, signer)
	}
	return ret
}
