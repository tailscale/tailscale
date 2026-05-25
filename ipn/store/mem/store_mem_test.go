// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mem

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"tailscale.com/ipn"
)

func TestNew(t *testing.T) {
	store, err := New(t.Logf, "test-id")
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if store == nil {
		t.Fatal("New() returned nil store")
	}

	// Verify it implements ipn.StateStore
	var _ ipn.StateStore = store
}

func TestStore_String(t *testing.T) {
	s := &Store{}
	if got := s.String(); got != "mem.Store" {
		t.Errorf("String() = %q, want %q", got, "mem.Store")
	}
}

func TestStore_ReadWriteState(t *testing.T) {
	s := &Store{}

	key := ipn.StateKey("test-key")
	data := []byte("test data")

	// Write state
	err := s.WriteState(key, data)
	if err != nil {
		t.Fatalf("WriteState() failed: %v", err)
	}

	// Read state
	got, err := s.ReadState(key)
	if err != nil {
		t.Fatalf("ReadState() failed: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("ReadState() = %q, want %q", got, data)
	}
}

func TestStore_ReadState_NotExist(t *testing.T) {
	s := &Store{}

	key := ipn.StateKey("nonexistent")
	_, err := s.ReadState(key)

	if !errors.Is(err, ipn.ErrStateNotExist) {
		t.Errorf("ReadState() error = %v, want ErrStateNotExist", err)
	}
}

func TestStore_WriteState_Clone(t *testing.T) {
	s := &Store{}

	key := ipn.StateKey("test-key")
	data := []byte("original data")

	err := s.WriteState(key, data)
	if err != nil {
		t.Fatalf("WriteState() failed: %v", err)
	}

	// Modify original data
	data[0] = 'X'

	// Read should return unmodified data
	got, err := s.ReadState(key)
	if err != nil {
		t.Fatalf("ReadState() failed: %v", err)
	}

	if bytes.Equal(got, data) {
		t.Error("ReadState() returned data that was modified after write (not cloned)")
	}

	if got[0] != 'o' {
		t.Errorf("ReadState() data was modified, got[0] = %c, want 'o'", got[0])
	}
}

func TestStore_MultipleKeys(t *testing.T) {
	s := &Store{}

	keys := []ipn.StateKey{"key1", "key2", "key3"}
	values := [][]byte{
		[]byte("value1"),
		[]byte("value2"),
		[]byte("value3"),
	}

	// Write all keys
	for i, key := range keys {
		if err := s.WriteState(key, values[i]); err != nil {
			t.Fatalf("WriteState(%s) failed: %v", key, err)
		}
	}

	// Read and verify all keys
	for i, key := range keys {
		got, err := s.ReadState(key)
		if err != nil {
			t.Fatalf("ReadState(%s) failed: %v", key, err)
		}
		if !bytes.Equal(got, values[i]) {
			t.Errorf("ReadState(%s) = %q, want %q", key, got, values[i])
		}
	}
}

func TestStore_Overwrite(t *testing.T) {
	s := &Store{}

	key := ipn.StateKey("test-key")

	// Write initial value
	if err := s.WriteState(key, []byte("first")); err != nil {
		t.Fatalf("WriteState() failed: %v", err)
	}

	// Overwrite with new value
	if err := s.WriteState(key, []byte("second")); err != nil {
		t.Fatalf("WriteState() failed: %v", err)
	}

	// Read should return latest value
	got, err := s.ReadState(key)
	if err != nil {
		t.Fatalf("ReadState() failed: %v", err)
	}

	if string(got) != "second" {
		t.Errorf("ReadState() = %q, want %q", got, "second")
	}
}

func TestStore_ExportToJSON_Empty(t *testing.T) {
	s := &Store{}

	data, err := s.ExportToJSON()
	if err != nil {
		t.Fatalf("ExportToJSON() failed: %v", err)
	}

	// Empty store should export as {}
	if string(data) != "{}" {
		t.Errorf("ExportToJSON() = %q, want %q", data, "{}")
	}
}

func TestStore_ExportToJSON_WithData(t *testing.T) {
	s := &Store{}

	s.WriteState("key1", []byte("value1"))
	s.WriteState("key2", []byte("value2"))

	data, err := s.ExportToJSON()
	if err != nil {
		t.Fatalf("ExportToJSON() failed: %v", err)
	}

	// Parse JSON to verify structure
	var result map[string][]byte
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("ExportToJSON() produced invalid JSON: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("ExportToJSON() exported %d keys, want 2", len(result))
	}

	if !bytes.Equal(result["key1"], []byte("value1")) {
		t.Errorf("ExportToJSON() key1 = %q, want %q", result["key1"], "value1")
	}
	if !bytes.Equal(result["key2"], []byte("value2")) {
		t.Errorf("ExportToJSON() key2 = %q, want %q", result["key2"], "value2")
	}
}

func TestStore_LoadFromJSON(t *testing.T) {
	s := &Store{}

	jsonData := `{
		"key1": "dmFsdWUx",
		"key2": "dmFsdWUy"
	}`

	err := s.LoadFromJSON([]byte(jsonData))
	if err != nil {
		t.Fatalf("LoadFromJSON() failed: %v", err)
	}

	// Verify loaded data
	got1, err := s.ReadState("key1")
	if err != nil {
		t.Fatalf("ReadState(key1) failed: %v", err)
	}

	got2, err := s.ReadState("key2")
	if err != nil {
		t.Fatalf("ReadState(key2) failed: %v", err)
	}

	if string(got1) != "value1" {
		t.Errorf("ReadState(key1) = %q, want %q", got1, "value1")
	}
	if string(got2) != "value2" {
		t.Errorf("ReadState(key2) = %q, want %q", got2, "value2")
	}
}

func TestStore_LoadFromJSON_Invalid(t *testing.T) {
	s := &Store{}

	err := s.LoadFromJSON([]byte("invalid json"))
	if err == nil {
		t.Error("LoadFromJSON() with invalid JSON succeeded, want error")
	}
}

func TestStore_ExportImportRoundTrip(t *testing.T) {
	s1 := &Store{}

	// Write some data
	s1.WriteState("key1", []byte("value1"))
	s1.WriteState("key2", []byte("value2"))
	s1.WriteState("key3", []byte("value3"))

	// Export
	exported, err := s1.ExportToJSON()
	if err != nil {
		t.Fatalf("ExportToJSON() failed: %v", err)
	}

	// Import into new store
	s2 := &Store{}
	if err := s2.LoadFromJSON(exported); err != nil {
		t.Fatalf("LoadFromJSON() failed: %v", err)
	}

	// Verify all data matches
	keys := []ipn.StateKey{"key1", "key2", "key3"}
	for _, key := range keys {
		val1, err1 := s1.ReadState(key)
		val2, err2 := s2.ReadState(key)

		if err1 != nil || err2 != nil {
			t.Fatalf("ReadState(%s) failed: err1=%v, err2=%v", key, err1, err2)
		}

		if !bytes.Equal(val1, val2) {
			t.Errorf("Round-trip failed for %s: %q != %q", key, val1, val2)
		}
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	s := &Store{}

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := ipn.StateKey(string(rune('a' + n%26)))
			s.WriteState(key, []byte{byte(n)})
		}(i)
	}

	wg.Wait()

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := ipn.StateKey(string(rune('a' + n%26)))
			_, _ = s.ReadState(key)
		}(i)
	}

	wg.Wait()
}

func TestStore_EmptyKey(t *testing.T) {
	s := &Store{}

	key := ipn.StateKey("")
	data := []byte("empty key data")

	// Should be able to use empty key
	if err := s.WriteState(key, data); err != nil {
		t.Fatalf("WriteState() with empty key failed: %v", err)
	}

	got, err := s.ReadState(key)
	if err != nil {
		t.Fatalf("ReadState() with empty key failed: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("ReadState() = %q, want %q", got, data)
	}
}

func TestStore_NilData(t *testing.T) {
	s := &Store{}

	key := ipn.StateKey("test")

	// Write nil data
	if err := s.WriteState(key, nil); err != nil {
		t.Fatalf("WriteState() with nil data failed: %v", err)
	}

	got, err := s.ReadState(key)
	if err != nil {
		t.Fatalf("ReadState() failed: %v", err)
	}

	if got != nil && len(got) != 0 {
		t.Errorf("ReadState() = %v, want nil or empty", got)
	}
}

// Benchmark operations
func BenchmarkStore_WriteState(b *testing.B) {
	s := &Store{}
	key := ipn.StateKey("bench-key")
	data := []byte("benchmark data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.WriteState(key, data)
	}
}

func BenchmarkStore_ReadState(b *testing.B) {
	s := &Store{}
	key := ipn.StateKey("bench-key")
	s.WriteState(key, []byte("benchmark data"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ReadState(key)
	}
}

func BenchmarkStore_ExportToJSON(b *testing.B) {
	s := &Store{}
	for i := 0; i < 100; i++ {
		key := ipn.StateKey(string(rune('a' + i%26)))
		s.WriteState(key, []byte("data"))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.ExportToJSON()
	}
}
