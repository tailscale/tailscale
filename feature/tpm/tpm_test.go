// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"bytes"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	"tailscale.com/ipn"
)

func TestPropToString(t *testing.T) {
	for prop, want := range map[uint32]string{
		0:          "",
		0x4D534654: "MSFT",
		0x414D4400: "AMD",
		0x414D440D: "AMD",
	} {
		if got := propToString(prop); got != want {
			t.Errorf("propToString(0x%x): got %q, want %q", prop, got, want)
		}
	}
}

func skipWithoutTPM(t *testing.T) {
	tpm, err := open()
	if err != nil {
		t.Skip("TPM not available")
	}
	tpm.Close()
}

func TestSealUnseal(t *testing.T) {
	skipWithoutTPM(t)

	data := make([]byte, 100*1024)
	rand.Read(data)

	sealed, err := seal(t.Logf, data)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed, data) {
		t.Fatalf("sealed data %q contains original input %q", sealed, data)
	}

	unsealed, err := unseal(t.Logf, sealed)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(data, unsealed) {
		t.Errorf("got unsealed data: %q, want: %q", unsealed, data)
	}
}

func TestStore(t *testing.T) {
	skipWithoutTPM(t)

	path := storePrefix + filepath.Join(t.TempDir(), "state")
	store, err := newStore(t.Logf, path)
	if err != nil {
		t.Fatal(err)
	}

	checkState := func(t *testing.T, store ipn.StateStore, k ipn.StateKey, want []byte) {
		got, err := store.ReadState(k)
		if err != nil {
			t.Errorf("ReadState(%q): %v", k, err)
		}
		if !bytes.Equal(want, got) {
			t.Errorf("ReadState(%q): got %q, want %q", k, got, want)
		}
	}

	k1, k2 := ipn.StateKey("k1"), ipn.StateKey("k2")
	v1, v2 := []byte("v1"), []byte("v2")

	t.Run("read-non-existent-key", func(t *testing.T) {
		_, err := store.ReadState(k1)
		if !errors.Is(err, ipn.ErrStateNotExist) {
			t.Errorf("ReadState succeeded, want %v", ipn.ErrStateNotExist)
		}
	})

	t.Run("read-write-k1", func(t *testing.T) {
		if err := store.WriteState(k1, v1); err != nil {
			t.Errorf("WriteState(%q, %q): %v", k1, v1, err)
		}
		checkState(t, store, k1, v1)
	})

	t.Run("read-write-k2", func(t *testing.T) {
		if err := store.WriteState(k2, v2); err != nil {
			t.Errorf("WriteState(%q, %q): %v", k2, v2, err)
		}
		checkState(t, store, k2, v2)
	})

	t.Run("update-k2", func(t *testing.T) {
		v2 = []byte("new v2")
		if err := store.WriteState(k2, v2); err != nil {
			t.Errorf("WriteState(%q, %q): %v", k2, v2, err)
		}
		checkState(t, store, k2, v2)
	})

	t.Run("reopen-store", func(t *testing.T) {
		store, err := newStore(t.Logf, path)
		if err != nil {
			t.Fatal(err)
		}
		checkState(t, store, k1, v1)
		checkState(t, store, k2, v2)
	})
}
