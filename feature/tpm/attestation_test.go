// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"runtime"
	"sync"
	"testing"
)

func TestAttestationKeySign(t *testing.T) {
	skipWithoutTPM(t)
	ak, err := newAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ak.Close(); err != nil {
			t.Errorf("ak.Close: %v", err)
		}
	})

	data := []byte("secrets")
	digest := sha256.Sum256(data)

	// Check signature/validation round trip.
	sig, err := ak.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(ak.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Errorf("ecdsa.VerifyASN1 failed")
	}

	// Create a different key.
	ak2, err := newAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ak2.Close(); err != nil {
			t.Errorf("ak2.Close: %v", err)
		}
	})

	// Make sure that the keys are distinct via their public keys and the
	// signatures they produce.
	if ak.Public().(*ecdsa.PublicKey).Equal(ak2.Public()) {
		t.Errorf("public keys of distinct attestation keys are the same")
	}
	sig2, err := ak2.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig, sig2) {
		t.Errorf("signatures from distinct attestation keys are the same")
	}
}

func TestAttestationKeySignConcurrent(t *testing.T) {
	skipWithoutTPM(t)
	ak, err := newAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ak.Close(); err != nil {
			t.Errorf("ak.Close: %v", err)
		}
	})

	data := []byte("secrets")
	digest := sha256.Sum256(data)

	wg := sync.WaitGroup{}
	for range runtime.GOMAXPROCS(-1) {
		wg.Go(func() {
			// Check signature/validation round trip.
			sig, err := ak.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if !ecdsa.VerifyASN1(ak.Public().(*ecdsa.PublicKey), digest[:], sig) {
				t.Errorf("ecdsa.VerifyASN1 failed")
			}
		})
	}
	wg.Wait()
}

func TestAttestationKeyUnmarshal(t *testing.T) {
	skipWithoutTPM(t)
	ak, err := newAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ak.Close(); err != nil {
			t.Errorf("ak.Close: %v", err)
		}
	})

	buf, err := ak.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var ak2 attestationKey
	if err := json.Unmarshal(buf, &ak2); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ak2.Close(); err != nil {
			t.Errorf("ak2.Close: %v", err)
		}
	})

	if !ak2.loaded() {
		t.Error("unmarshalled key is not loaded")
	}

	if !ak.Public().(*ecdsa.PublicKey).Equal(ak2.Public()) {
		t.Error("unmarshalled public key is not the same as the original public key")
	}
}

func TestAttestationKeyClone(t *testing.T) {
	skipWithoutTPM(t)
	ak, err := newAttestationKey()
	if err != nil {
		t.Fatal(err)
	}

	ak2 := ak.Clone()
	if ak2 == nil {
		t.Fatal("Clone failed")
	}
	t.Cleanup(func() {
		if err := ak2.Close(); err != nil {
			t.Errorf("ak2.Close: %v", err)
		}
	})
	// Close the original key, ak2 should remain open and usable.
	if err := ak.Close(); err != nil {
		t.Fatal(err)
	}

	data := []byte("secrets")
	digest := sha256.Sum256(data)
	// Check signature/validation round trip using cloned key.
	sig, err := ak2.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(ak2.Public().(*ecdsa.PublicKey), digest[:], sig) {
		t.Errorf("ecdsa.VerifyASN1 failed")
	}
}
