// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tpm

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store"
	"tailscale.com/types/logger"
	"tailscale.com/util/mak"
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

func skipWithoutTPM(t testing.TB) {
	if !tpmSupported() {
		t.Skip("TPM not available")
	}
}

func TestSealUnseal(t *testing.T) {
	skipWithoutTPM(t)

	data := make([]byte, 100*1024)
	rand.Read(data)
	var key [32]byte
	rand.Read(key[:])

	sealed, err := seal(t.Logf, decryptedData{Key: key, Data: data})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(sealed.Data, data) {
		t.Fatalf("sealed data %q contains original input %q", sealed.Data, data)
	}

	unsealed, err := unseal(t.Logf, *sealed)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(data, unsealed.Data) {
		t.Errorf("got unsealed data: %q, want: %q", unsealed, data)
	}
	if key != unsealed.Key {
		t.Errorf("got unsealed key: %q, want: %q", unsealed.Key, key)
	}
}

func TestStore(t *testing.T) {
	skipWithoutTPM(t)

	path := store.TPMPrefix + filepath.Join(t.TempDir(), "state")
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

func BenchmarkStore(b *testing.B) {
	skipWithoutTPM(b)
	b.StopTimer()

	stores := make(map[string]ipn.StateStore)
	key := ipn.StateKey(b.Name())

	// Set up tpmStore
	tpmStore, err := newStore(b.Logf, filepath.Join(b.TempDir(), "tpm.store"))
	if err != nil {
		b.Fatal(err)
	}
	if err := tpmStore.WriteState(key, []byte("-1")); err != nil {
		b.Fatal(err)
	}
	stores["tpmStore"] = tpmStore

	// Set up FileStore
	fileStore, err := store.NewFileStore(b.Logf, filepath.Join(b.TempDir(), "file.store"))
	if err != nil {
		b.Fatal(err)
	}
	if err := fileStore.WriteState(key, []byte("-1")); err != nil {
		b.Fatal(err)
	}
	stores["fileStore"] = fileStore

	b.StartTimer()

	for name, store := range stores {
		b.Run(name, func(b *testing.B) {
			b.Run("write-noop", func(b *testing.B) {
				for range b.N {
					if err := store.WriteState(key, []byte("-1")); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("write", func(b *testing.B) {
				for i := range b.N {
					if err := store.WriteState(key, []byte(strconv.Itoa(i))); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("read", func(b *testing.B) {
				for range b.N {
					if _, err := store.ReadState(key); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

func TestMigrateStateToTPM(t *testing.T) {
	if !tpmSupported() {
		t.Logf("using mock tpmseal provider")
		store.RegisterForTest(t, store.TPMPrefix, newMockTPMSeal)
	}

	storePath := filepath.Join(t.TempDir(), "store")
	// Make sure migration doesn't cause a failure when no state file exists.
	if _, err := store.New(t.Logf, store.TPMPrefix+storePath); err != nil {
		t.Fatalf("store.New failed for new tpmseal store: %v", err)
	}
	os.Remove(storePath)

	initial, err := store.New(t.Logf, storePath)
	if err != nil {
		t.Fatalf("store.New failed for new file store: %v", err)
	}

	// Populate initial state file.
	content := map[ipn.StateKey][]byte{
		"foo": []byte("bar"),
		"baz": []byte("qux"),
	}
	for k, v := range content {
		if err := initial.WriteState(k, v); err != nil {
			t.Fatal(err)
		}
	}
	// Expected file keys for plaintext and sealed versions of state.
	keysPlaintext := []string{"foo", "baz"}
	keysTPMSeal := []string{"key", "nonce", "data"}

	for _, tt := range []struct {
		desc     string
		path     string
		wantKeys []string
	}{
		{
			desc:     "plaintext-to-plaintext",
			path:     storePath,
			wantKeys: keysPlaintext,
		},
		{
			desc:     "plaintext-to-tpmseal",
			path:     store.TPMPrefix + storePath,
			wantKeys: keysTPMSeal,
		},
		{
			desc:     "tpmseal-to-tpmseal",
			path:     store.TPMPrefix + storePath,
			wantKeys: keysTPMSeal,
		},
		{
			desc:     "tpmseal-to-plaintext",
			path:     storePath,
			wantKeys: keysPlaintext,
		},
	} {
		t.Run(tt.desc, func(t *testing.T) {
			s, err := store.New(t.Logf, tt.path)
			if err != nil {
				t.Fatalf("migration failed: %v", err)
			}
			gotContent := maps.Collect(s.(interface {
				All() iter.Seq2[ipn.StateKey, []byte]
			}).All())
			if diff := cmp.Diff(content, gotContent); diff != "" {
				t.Errorf("unexpected content after migration, diff:\n%s", diff)
			}

			buf, err := os.ReadFile(storePath)
			if err != nil {
				t.Fatal(err)
			}
			var data map[string]any
			if err := json.Unmarshal(buf, &data); err != nil {
				t.Fatal(err)
			}
			gotKeys := slices.Collect(maps.Keys(data))
			slices.Sort(gotKeys)
			slices.Sort(tt.wantKeys)
			if diff := cmp.Diff(gotKeys, tt.wantKeys); diff != "" {
				t.Errorf("unexpected content keys after migration, diff:\n%s", diff)
			}
		})
	}
}

type mockTPMSealProvider struct {
	path string
	data map[ipn.StateKey][]byte
}

func newMockTPMSeal(logf logger.Logf, path string) (ipn.StateStore, error) {
	path, ok := strings.CutPrefix(path, store.TPMPrefix)
	if !ok {
		return nil, fmt.Errorf("%q missing tpmseal: prefix", path)
	}
	s := &mockTPMSealProvider{path: path}
	buf, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, s.flushState()
	}
	if err != nil {
		return nil, err
	}
	var data struct {
		Key   string
		Nonce string
		Data  map[ipn.StateKey][]byte
	}
	if err := json.Unmarshal(buf, &data); err != nil {
		return nil, err
	}
	if data.Key == "" || data.Nonce == "" {
		return nil, fmt.Errorf("%q missing key or nonce", path)
	}
	s.data = data.Data
	return s, nil
}

func (p *mockTPMSealProvider) ReadState(k ipn.StateKey) ([]byte, error) {
	return p.data[k], nil
}

func (p *mockTPMSealProvider) WriteState(k ipn.StateKey, v []byte) error {
	mak.Set(&p.data, k, v)
	return p.flushState()
}

func (p *mockTPMSealProvider) All() iter.Seq2[ipn.StateKey, []byte] {
	return maps.All(p.data)
}

func (p *mockTPMSealProvider) flushState() error {
	data := map[string]any{
		"key":   "foo",
		"nonce": "bar",
		"data":  p.data,
	}
	buf, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(p.path, buf, 0600)
}
