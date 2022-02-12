// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows && cgo
// +build windows,cgo

package controlclient

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tailscale/certstore"
)

const (
	testRootCommonName = "testroot"
	testRootSubject    = "CN=testroot"
)

type testIdentity struct {
	chain []*x509.Certificate
}

func makeChain(rootCommonName string, notBefore, notAfter time.Time) []*x509.Certificate {
	return []*x509.Certificate{
		{
			NotBefore:          notBefore,
			NotAfter:           notAfter,
			PublicKeyAlgorithm: x509.RSA,
		},
		{
			Subject: pkix.Name{
				CommonName: rootCommonName,
			},
			PublicKeyAlgorithm: x509.RSA,
		},
	}
}

func (t *testIdentity) Certificate() (*x509.Certificate, error) {
	return t.chain[0], nil
}

func (t *testIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return t.chain, nil
}

func (t *testIdentity) Signer() (crypto.Signer, error) {
	return nil, errors.New("not implemented")
}

func (t *testIdentity) Delete() error {
	return errors.New("not implemented")
}

func (t *testIdentity) Close() {}

func TestSelectIdentityFromSlice(t *testing.T) {
	var times []time.Time
	for _, ts := range []string{
		"2000-01-01T00:00:00Z",
		"2001-01-01T00:00:00Z",
		"2002-01-01T00:00:00Z",
		"2003-01-01T00:00:00Z",
	} {
		tm, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t.Fatal(err)
		}
		times = append(times, tm)
	}

	tests := []struct {
		name    string
		subject string
		ids     []certstore.Identity
		now     time.Time
		// wantIndex is an index into ids, or -1 for nil.
		wantIndex int
	}{
		{
			name:    "single unexpired identity",
			subject: testRootSubject,
			ids: []certstore.Identity{
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[2]),
				},
			},
			now:       times[1],
			wantIndex: 0,
		},
		{
			name:    "single expired identity",
			subject: testRootSubject,
			ids: []certstore.Identity{
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[1]),
				},
			},
			now:       times[2],
			wantIndex: -1,
		},
		{
			name:    "unrelated ids",
			subject: testRootSubject,
			ids: []certstore.Identity{
				&testIdentity{
					chain: makeChain("something", times[0], times[2]),
				},
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[2]),
				},
				&testIdentity{
					chain: makeChain("else", times[0], times[2]),
				},
			},
			now:       times[1],
			wantIndex: 1,
		},
		{
			name:    "expired with unrelated ids",
			subject: testRootSubject,
			ids: []certstore.Identity{
				&testIdentity{
					chain: makeChain("something", times[0], times[3]),
				},
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[1]),
				},
				&testIdentity{
					chain: makeChain("else", times[0], times[3]),
				},
			},
			now:       times[2],
			wantIndex: -1,
		},
		{
			name:    "one expired",
			subject: testRootSubject,
			ids: []certstore.Identity{
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[1]),
				},
				&testIdentity{
					chain: makeChain(testRootCommonName, times[1], times[3]),
				},
			},
			now:       times[2],
			wantIndex: 1,
		},
		{
			name:    "two certs both unexpired",
			subject: testRootSubject,
			ids: []certstore.Identity{
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[3]),
				},
				&testIdentity{
					chain: makeChain(testRootCommonName, times[1], times[3]),
				},
			},
			now:       times[2],
			wantIndex: 1,
		},
		{
			name:    "two unexpired one expired",
			subject: testRootSubject,
			ids: []certstore.Identity{
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[3]),
				},
				&testIdentity{
					chain: makeChain(testRootCommonName, times[1], times[3]),
				},
				&testIdentity{
					chain: makeChain(testRootCommonName, times[0], times[1]),
				},
			},
			now:       times[2],
			wantIndex: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotId, gotChain := selectIdentityFromSlice(tt.subject, tt.ids, tt.now)

			if gotId == nil && gotChain != nil {
				t.Error("id is nil: got non-nil chain, want nil chain")
				return
			}
			if gotId != nil && gotChain == nil {
				t.Error("id is not nil: got nil chain, want non-nil chain")
				return
			}
			if tt.wantIndex == -1 {
				if gotId != nil {
					t.Error("got non-nil id, want nil id")
				}
				return
			}
			if gotId == nil {
				t.Error("got nil id, want non-nil id")
				return
			}
			if gotId != tt.ids[tt.wantIndex] {
				found := -1
				for i := range tt.ids {
					if tt.ids[i] == gotId {
						found = i
						break
					}
				}
				if found == -1 {
					t.Errorf("got unknown id, want id at index %v", tt.wantIndex)
				} else {
					t.Errorf("got id at index %v, want id at index %v", found, tt.wantIndex)
				}
			}

			tid, ok := tt.ids[tt.wantIndex].(*testIdentity)
			if !ok {
				t.Error("got non-testIdentity, want testIdentity")
				return
			}

			if !reflect.DeepEqual(tid.chain, gotChain) {
				t.Errorf("got unknown chain, want chain from id at index %v", tt.wantIndex)
			}
		})
	}
}
