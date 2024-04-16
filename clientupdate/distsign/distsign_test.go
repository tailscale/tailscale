// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package distsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/blake2s"
)

func TestDownload(t *testing.T) {
	srv := newTestServer(t)
	c := srv.client(t)

	tests := []struct {
		desc    string
		before  func(*testing.T)
		src     string
		want    []byte
		wantErr bool
	}{
		{
			desc:    "missing file",
			before:  func(*testing.T) {},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "success",
			before: func(*testing.T) {
				srv.addSigned("hello", []byte("world"))
			},
			src:  "hello",
			want: []byte("world"),
		},
		{
			desc: "no signature",
			before: func(*testing.T) {
				srv.add("hello", []byte("world"))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "bad signature",
			before: func(*testing.T) {
				srv.add("hello", []byte("world"))
				srv.add("hello.sig", []byte("potato"))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "signed with untrusted key",
			before: func(t *testing.T) {
				srv.add("hello", []byte("world"))
				srv.add("hello.sig", newSigningKeyPair(t).sign([]byte("world")))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "signed with root key",
			before: func(t *testing.T) {
				srv.add("hello", []byte("world"))
				srv.add("hello.sig", ed25519.Sign(srv.roots[0].k, []byte("world")))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "bad signing key signature",
			before: func(t *testing.T) {
				srv.add("distsign.pub.sig", []byte("potato"))
				srv.addSigned("hello", []byte("world"))
			},
			src:     "hello",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			srv.reset()
			tt.before(t)

			dst := filepath.Join(t.TempDir(), tt.src)
			t.Cleanup(func() {
				os.Remove(dst)
			})
			err := c.Download(context.Background(), tt.src, dst)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("unexpected error from Download(%q): %v", tt.src, err)
			}
			if tt.wantErr {
				t.Fatalf("Download(%q) succeeded, expected an error", tt.src)
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(tt.want, got) {
				t.Errorf("Download(%q): got %q, want %q", tt.src, got, tt.want)
			}
		})
	}
}

func TestValidateLocalBinary(t *testing.T) {
	srv := newTestServer(t)
	c := srv.client(t)

	tests := []struct {
		desc    string
		before  func(*testing.T)
		src     string
		wantErr bool
	}{
		{
			desc:    "missing file",
			before:  func(*testing.T) {},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "success",
			before: func(*testing.T) {
				srv.addSigned("hello", []byte("world"))
			},
			src: "hello",
		},
		{
			desc: "contents changed",
			before: func(*testing.T) {
				srv.addSigned("hello", []byte("new world"))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "no signature",
			before: func(*testing.T) {
				srv.add("hello", []byte("world"))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "bad signature",
			before: func(*testing.T) {
				srv.add("hello", []byte("world"))
				srv.add("hello.sig", []byte("potato"))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "signed with untrusted key",
			before: func(t *testing.T) {
				srv.add("hello", []byte("world"))
				srv.add("hello.sig", newSigningKeyPair(t).sign([]byte("world")))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "signed with root key",
			before: func(t *testing.T) {
				srv.add("hello", []byte("world"))
				srv.add("hello.sig", ed25519.Sign(srv.roots[0].k, []byte("world")))
			},
			src:     "hello",
			wantErr: true,
		},
		{
			desc: "bad signing key signature",
			before: func(t *testing.T) {
				srv.add("distsign.pub.sig", []byte("potato"))
				srv.addSigned("hello", []byte("world"))
			},
			src:     "hello",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			srv.reset()

			// First just do a successful Download.
			want := []byte("world")
			srv.addSigned("hello", want)
			dst := filepath.Join(t.TempDir(), tt.src)
			err := c.Download(context.Background(), tt.src, dst)
			if err != nil {
				t.Fatalf("unexpected error from Download(%q): %v", tt.src, err)
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, got) {
				t.Errorf("Download(%q): got %q, want %q", tt.src, got, want)
			}

			// Now we reset srv with the test case and validate against the local dst.
			srv.reset()
			tt.before(t)

			err = c.ValidateLocalBinary(tt.src, dst)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("unexpected error from ValidateLocalBinary(%q): %v", tt.src, err)
			}
			if tt.wantErr {
				t.Fatalf("ValidateLocalBinary(%q) succeeded, expected an error", tt.src)
			}
		})
	}
}

func TestRotateRoot(t *testing.T) {
	srv := newTestServer(t)
	c1 := srv.client(t)
	ctx := context.Background()

	srv.addSigned("hello", []byte("world"))
	if err := c1.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed on a fresh server: %v", err)
	}

	// Remove first root and replace it with a new key.
	srv.roots = append(srv.roots[1:], newRootKeyPair(t))

	// Old client can still download files because it still trusts the old
	// root key.
	if err := c1.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after root rotation on old client: %v", err)
	}
	// New client should fail download because current signing key is signed by
	// the revoked root that new client doesn't trust.
	c2 := srv.client(t)
	if err := c2.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err == nil {
		t.Fatalf("Download succeeded on new client, but signing key is signed with revoked root key")
	}
	// Re-sign signing key with another valid root that client still trusts.
	srv.resignSigningKeys()
	// Both old and new clients should now be able to download.
	//
	// Note: we don't need to re-sign the "hello" file because signing key
	// didn't change (only signing key's signature).
	if err := c1.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after root rotation on old client with re-signed signing key: %v", err)
	}
	if err := c2.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after root rotation on new client with re-signed signing key: %v", err)
	}
}

func TestRotateSigning(t *testing.T) {
	srv := newTestServer(t)
	c := srv.client(t)
	ctx := context.Background()

	srv.addSigned("hello", []byte("world"))
	if err := c.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed on a fresh server: %v", err)
	}

	// Replace signing key but don't publish it yet.
	srv.sign = append(srv.sign, newSigningKeyPair(t))
	if err := c.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after new signing key added but before publishing it: %v", err)
	}

	// Publish new signing key bundle with both keys.
	srv.resignSigningKeys()
	if err := c.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after new signing key was published: %v", err)
	}

	// Re-sign the "hello" file with new signing key.
	srv.add("hello.sig", srv.sign[1].sign([]byte("world")))
	if err := c.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after re-signing with new signing key: %v", err)
	}

	// Drop the old signing key.
	srv.sign = srv.sign[1:]
	srv.resignSigningKeys()
	if err := c.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after removing old signing key: %v", err)
	}

	// Add another key and re-sign the file with it *before* publishing.
	srv.sign = append(srv.sign, newSigningKeyPair(t))
	srv.add("hello.sig", srv.sign[1].sign([]byte("world")))
	if err := c.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err == nil {
		t.Fatalf("Download succeeded when signed with a not-yet-published signing key")
	}
	// Fix this by publishing the new key.
	srv.resignSigningKeys()
	if err := c.Download(ctx, "hello", filepath.Join(t.TempDir(), "hello")); err != nil {
		t.Fatalf("Download failed after publishing new signing key: %v", err)
	}
}

func TestParseRootKey(t *testing.T) {
	tests := []struct {
		desc     string
		generate func() ([]byte, []byte, error)
		wantErr  bool
	}{
		{
			desc:     "valid",
			generate: GenerateRootKey,
		},
		{
			desc:     "signing",
			generate: GenerateSigningKey,
			wantErr:  true,
		},
		{
			desc:     "nil",
			generate: func() ([]byte, []byte, error) { return nil, nil, nil },
			wantErr:  true,
		},
		{
			desc: "invalid PEM tag",
			generate: func() ([]byte, []byte, error) {
				priv, pub, err := GenerateRootKey()
				priv = bytes.Replace(priv, []byte("ROOT "), nil, -1)
				return priv, pub, err
			},
			wantErr: true,
		},
		{
			desc:     "not PEM",
			generate: func() ([]byte, []byte, error) { return []byte("s3cr3t"), nil, nil },
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			priv, _, err := tt.generate()
			if err != nil {
				t.Fatal(err)
			}
			r, err := ParseRootKey(priv)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				t.Fatal("expected non-nil error")
			}
			if r == nil {
				t.Errorf("got nil error and nil RootKey")
			}
		})
	}
}

func TestParseSigningKey(t *testing.T) {
	tests := []struct {
		desc     string
		generate func() ([]byte, []byte, error)
		wantErr  bool
	}{
		{
			desc:     "valid",
			generate: GenerateSigningKey,
		},
		{
			desc:     "root",
			generate: GenerateRootKey,
			wantErr:  true,
		},
		{
			desc:     "nil",
			generate: func() ([]byte, []byte, error) { return nil, nil, nil },
			wantErr:  true,
		},
		{
			desc: "invalid PEM tag",
			generate: func() ([]byte, []byte, error) {
				priv, pub, err := GenerateSigningKey()
				priv = bytes.Replace(priv, []byte("SIGNING "), nil, -1)
				return priv, pub, err
			},
			wantErr: true,
		},
		{
			desc:     "not PEM",
			generate: func() ([]byte, []byte, error) { return []byte("s3cr3t"), nil, nil },
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			priv, _, err := tt.generate()
			if err != nil {
				t.Fatal(err)
			}
			r, err := ParseSigningKey(priv)
			if err != nil {
				if tt.wantErr {
					return
				}
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr {
				t.Fatal("expected non-nil error")
			}
			if r == nil {
				t.Errorf("got nil error and nil SigningKey")
			}
		})
	}
}

type testServer struct {
	roots []rootKeyPair
	sign  []signingKeyPair
	files map[string][]byte
	srv   *httptest.Server
}

func newTestServer(t *testing.T) *testServer {
	var roots []rootKeyPair
	for range 3 {
		roots = append(roots, newRootKeyPair(t))
	}

	ts := &testServer{
		roots: roots,
		sign:  []signingKeyPair{newSigningKeyPair(t)},
	}
	ts.reset()
	ts.srv = httptest.NewServer(ts)
	t.Cleanup(ts.srv.Close)
	return ts
}

func (s *testServer) client(t *testing.T) *Client {
	roots := make([]ed25519.PublicKey, 0, len(s.roots))
	for _, r := range s.roots {
		pub, err := parseSinglePublicKey(r.pubRaw, pemTypeRootPublic)
		if err != nil {
			t.Fatalf("parsePublicKey: %v", err)
		}
		roots = append(roots, pub)
	}
	u, err := url.Parse(s.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return &Client{
		logf:     t.Logf,
		roots:    roots,
		pkgsAddr: u,
	}
}

func (s *testServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	data, ok := s.files[path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(data)
}

func (s *testServer) addSigned(name string, data []byte) {
	s.files[name] = data
	s.files[name+".sig"] = s.sign[0].sign(data)
}

func (s *testServer) add(name string, data []byte) {
	s.files[name] = data
}

func (s *testServer) reset() {
	s.files = make(map[string][]byte)
	s.resignSigningKeys()
}

func (s *testServer) resignSigningKeys() {
	var pubs [][]byte
	for _, k := range s.sign {
		pubs = append(pubs, k.pubRaw)
	}
	bundle := bytes.Join(pubs, []byte("\n"))
	sig := s.roots[0].sign(bundle)
	s.files["distsign.pub"] = bundle
	s.files["distsign.pub.sig"] = sig
}

type rootKeyPair struct {
	*RootKey
	keyPair
}

func newRootKeyPair(t *testing.T) rootKeyPair {
	privRaw, pubRaw, err := GenerateRootKey()
	if err != nil {
		t.Fatalf("GenerateRootKey: %v", err)
	}
	kp := keyPair{
		privRaw: privRaw,
		pubRaw:  pubRaw,
	}
	priv, err := parsePrivateKey(kp.privRaw, pemTypeRootPrivate)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	return rootKeyPair{
		RootKey: &RootKey{k: priv},
		keyPair: kp,
	}
}

func (s rootKeyPair) sign(bundle []byte) []byte {
	sig, err := s.SignSigningKeys(bundle)
	if err != nil {
		panic(err)
	}
	return sig
}

type signingKeyPair struct {
	*SigningKey
	keyPair
}

func newSigningKeyPair(t *testing.T) signingKeyPair {
	privRaw, pubRaw, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("GenerateSigningKey: %v", err)
	}
	kp := keyPair{
		privRaw: privRaw,
		pubRaw:  pubRaw,
	}
	priv, err := parsePrivateKey(kp.privRaw, pemTypeSigningPrivate)
	if err != nil {
		t.Fatalf("parsePrivateKey: %v", err)
	}
	return signingKeyPair{
		SigningKey: &SigningKey{k: priv},
		keyPair:    kp,
	}
}

func (s signingKeyPair) sign(blob []byte) []byte {
	hash := blake2s.Sum256(blob)
	sig, err := s.SignPackageHash(hash[:], int64(len(blob)))
	if err != nil {
		panic(err)
	}
	return sig
}

type keyPair struct {
	privRaw []byte
	pubRaw  []byte
}
