// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package distsign implements signature and validation of arbitrary
// distributable files.
//
// There are 3 parties in this exchange:
//   - builder, which creates files, signs them with signing keys and publishes
//     to server
//   - server, which distributes public signing keys, files and signatures
//   - client, which downloads files and signatures from server, and validates
//     the signatures
//
// There are 2 types of keys:
//   - signing keys, that sign individual distributable files on the builder
//   - root keys, that sign signing keys and are kept offline
//
// root keys -(sign)-> signing keys -(sign)-> files
//
// All keys are asymmetric Ed25519 key pairs.
//
// The server serves static files under some known prefix. The kinds of files are:
//   - distsign.pub - bundle of PEM-encoded public signing keys
//   - distsign.pub.sig - signature of distsign.pub using one of the root keys
//   - $file - any distributable file
//   - $file.sig - signature of $file using any of the signing keys
//
// The root public keys are baked into the client software at compile time.
// These keys are long-lived and prove the validity of current signing keys
// from distsign.pub. To rotate root keys, a new client release must be
// published, they are not rotated dynamically. There are multiple root keys in
// different locations specifically to allow this rotation without using the
// discarded root key for any new signatures.
//
// The signing public keys are fetched by the client dynamically before every
// download and can be rotated more readily, assuming that most deployed
// clients trust the root keys used to issue fresh signing keys.
package distsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/hdevalence/ed25519consensus"
	"golang.org/x/crypto/blake2s"
)

const (
	pemTypeRootPrivate    = "ROOT PRIVATE KEY"
	pemTypeRootPublic     = "ROOT PUBLIC KEY"
	pemTypeSigningPrivate = "SIGNING PRIVATE KEY"
	pemTypeSigningPublic  = "SIGNING PUBLIC KEY"

	downloadSizeLimit    = 1 << 29 // 512MB
	signingKeysSizeLimit = 1 << 20 // 1MB
	signatureSizeLimit   = ed25519.SignatureSize
)

// RootKey is a root key used to sign signing keys.
type RootKey struct {
	k ed25519.PrivateKey
}

// GenerateRootKey generates a new root key pair and encodes it as PEM.
func GenerateRootKey() (priv, pub []byte, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
			Type:  pemTypeRootPrivate,
			Bytes: []byte(priv),
		}), pem.EncodeToMemory(&pem.Block{
			Type:  pemTypeRootPublic,
			Bytes: []byte(pub),
		}), nil
}

// ParseRootKey parses the PEM-encoded private root key. The key must be in the
// same format as returned by GenerateRootKey.
func ParseRootKey(privKey []byte) (*RootKey, error) {
	k, err := parsePrivateKey(privKey, pemTypeRootPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root key: %w", err)
	}
	return &RootKey{k: k}, nil
}

// SignSigningKeys signs the bundle of public signing keys. The bundle must be
// a sequence of PEM blocks joined with newlines.
func (r *RootKey) SignSigningKeys(pubBundle []byte) ([]byte, error) {
	if _, err := ParseSigningKeyBundle(pubBundle); err != nil {
		return nil, err
	}
	return ed25519.Sign(r.k, pubBundle), nil
}

// SigningKey is a signing key used to sign packages.
type SigningKey struct {
	k ed25519.PrivateKey
}

// GenerateSigningKey generates a new signing key pair and encodes it as PEM.
func GenerateSigningKey() (priv, pub []byte, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
			Type:  pemTypeSigningPrivate,
			Bytes: []byte(priv),
		}), pem.EncodeToMemory(&pem.Block{
			Type:  pemTypeSigningPublic,
			Bytes: []byte(pub),
		}), nil
}

// ParseSigningKey parses the PEM-encoded private signing key. The key must be
// in the same format as returned by GenerateSigningKey.
func ParseSigningKey(privKey []byte) (*SigningKey, error) {
	k, err := parsePrivateKey(privKey, pemTypeSigningPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root key: %w", err)
	}
	return &SigningKey{k: k}, nil
}

// SignPackageHash signs the hash and the length of a package. Use PackageHash
// to compute the inputs.
func (s *SigningKey) SignPackageHash(hash []byte, len int64) ([]byte, error) {
	if len <= 0 {
		return nil, fmt.Errorf("package length must be positive, got %d", len)
	}
	msg := binary.LittleEndian.AppendUint64(hash, uint64(len))
	return ed25519.Sign(s.k, msg), nil
}

// PackageHash is a hash.Hash that counts the number of bytes written. Use it
// to get the hash and length inputs to SigningKey.SignPackageHash.
type PackageHash struct {
	hash.Hash
	len int64
}

// NewPackageHash returns an initialized PackageHash using BLAKE2s.
func NewPackageHash() *PackageHash {
	h, err := blake2s.New256(nil)
	if err != nil {
		// Should never happen with a nil key passed to blake2s.
		panic(err)
	}
	return &PackageHash{Hash: h}
}

func (ph *PackageHash) Write(b []byte) (int, error) {
	ph.len += int64(len(b))
	return ph.Hash.Write(b)
}

// Reset the PackageHash to its initial state.
func (ph *PackageHash) Reset() {
	ph.len = 0
	ph.Hash.Reset()
}

// Len returns the total number of bytes written.
func (ph *PackageHash) Len() int64 { return ph.len }

// Client downloads and validates files from a distribution server.
type Client struct {
	roots    []ed25519.PublicKey
	pkgsAddr *url.URL
}

// NewClient returns a new client for distribution server located at pkgsAddr,
// and uses embedded root keys from the roots/ subdirectory of this package.
func NewClient(pkgsAddr string) (*Client, error) {
	u, err := url.Parse(pkgsAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid pkgsAddr %q: %w", pkgsAddr, err)
	}
	return &Client{roots: roots(), pkgsAddr: u}, nil
}

func (c *Client) url(path string) string {
	return c.pkgsAddr.JoinPath(path).String()
}

// Download fetches a file at path srcPath from pkgsAddr passed in NewClient.
// The file is downloaded to dstPath and its signature is validated using the
// embedded root keys. Download returns an error if anything goes wrong with
// the actual file download or with signature validation.
func (c *Client) Download(srcPath, dstPath string) error {
	// Always fetch a fresh signing key.
	sigPub, err := c.signingKeys()
	if err != nil {
		return err
	}

	srcURL := c.url(srcPath)
	sigURL := srcURL + ".sig"

	dstPathUnverified := dstPath + ".unverified"
	hash, len, err := download(srcURL, dstPathUnverified, downloadSizeLimit)
	if err != nil {
		return err
	}
	sig, err := fetch(sigURL, signatureSizeLimit)
	if err != nil {
		// Best-effort clean up of downloaded package.
		os.Remove(dstPathUnverified)
		return err
	}
	msg := binary.LittleEndian.AppendUint64(hash, uint64(len))
	if !VerifyAny(sigPub, msg, sig) {
		// Best-effort clean up of downloaded package.
		os.Remove(dstPathUnverified)
		return fmt.Errorf("signature %q for key %q does not validate with the current release signing key; either you are under attack, or attempting to download an old version of Tailscale which was signed with an older signing key", sigURL, srcURL)
	}

	if err := os.Rename(dstPathUnverified, dstPath); err != nil {
		return fmt.Errorf("failed to move %q to %q after signature validation", dstPathUnverified, dstPath)
	}

	return nil
}

// signingKeys fetches current signing keys from the server and validates them
// against the roots. Should be called before validation of any downloaded file
// to get the fresh keys.
func (c *Client) signingKeys() ([]ed25519.PublicKey, error) {
	keyURL := c.url("distsign.pub")
	sigURL := keyURL + ".sig"
	raw, err := fetch(keyURL, signingKeysSizeLimit)
	if err != nil {
		return nil, err
	}
	sig, err := fetch(sigURL, signatureSizeLimit)
	if err != nil {
		return nil, err
	}
	if !VerifyAny(c.roots, raw, sig) {
		return nil, fmt.Errorf("signature %q for key %q does not validate with any known root key; either you are under attack, or running a very old version of Tailscale with outdated root keys", sigURL, keyURL)
	}

	keys, err := ParseSigningKeyBundle(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse signing key bundle from %q: %w", keyURL, err)
	}
	return keys, nil
}

// fetch reads the response body from url into memory, up to limit bytes.
func fetch(url string, limit int64) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// download writes the response body of url into a local file at dst, up to
// limit bytes. On success, the returned value is a BLAKE2s hash of the file.
func download(url, dst string, limit int64) ([]byte, int64, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	h := NewPackageHash()
	r := io.TeeReader(io.LimitReader(resp.Body, limit), h)

	f, err := os.Create(dst)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return nil, 0, err
	}
	if err := f.Close(); err != nil {
		return nil, 0, err
	}

	return h.Sum(nil), h.Len(), nil
}

func parsePrivateKey(data []byte, typeTag string) (ed25519.PrivateKey, error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return nil, errors.New("failed to decode PEM data")
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing PEM data")
	}
	if b.Type != typeTag {
		return nil, fmt.Errorf("PEM type is %q, want %q", b.Type, typeTag)
	}
	if len(b.Bytes) != ed25519.PrivateKeySize {
		return nil, errors.New("private key has incorrect length for an Ed25519 private key")
	}
	return ed25519.PrivateKey(b.Bytes), nil
}

// ParseSigningKeyBundle parses the bundle of PEM-encoded public signing keys.
func ParseSigningKeyBundle(bundle []byte) ([]ed25519.PublicKey, error) {
	return parsePublicKeyBundle(bundle, pemTypeSigningPublic)
}

// ParseRootKeyBundle parses the bundle of PEM-encoded public root keys.
func ParseRootKeyBundle(bundle []byte) ([]ed25519.PublicKey, error) {
	return parsePublicKeyBundle(bundle, pemTypeRootPublic)
}

func parsePublicKeyBundle(bundle []byte, typeTag string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for len(bundle) > 0 {
		pub, rest, err := parsePublicKey(bundle, typeTag)
		if err != nil {
			return nil, err
		}
		keys = append(keys, pub)
		bundle = rest
	}
	if len(keys) == 0 {
		return nil, errors.New("no signing keys found in the bundle")
	}
	return keys, nil
}

func parseSinglePublicKey(data []byte, typeTag string) (ed25519.PublicKey, error) {
	pub, rest, err := parsePublicKey(data, typeTag)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("trailing PEM data")
	}
	return pub, err
}

func parsePublicKey(data []byte, typeTag string) (pub ed25519.PublicKey, rest []byte, retErr error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return nil, nil, errors.New("failed to decode PEM data")
	}
	if b.Type != typeTag {
		return nil, nil, fmt.Errorf("PEM type is %q, want %q", b.Type, typeTag)
	}
	if len(b.Bytes) != ed25519.PublicKeySize {
		return nil, nil, errors.New("public key has incorrect length for an Ed25519 public key")
	}
	return ed25519.PublicKey(b.Bytes), rest, nil
}

// VerifyAny verifies whether sig is valid for msg using any of the keys.
// VerifyAny will panic if any of the keys have the wrong size for Ed25519.
func VerifyAny(keys []ed25519.PublicKey, msg, sig []byte) bool {
	for _, k := range keys {
		if ed25519consensus.Verify(k, msg, sig) {
			return true
		}
	}
	return false
}
