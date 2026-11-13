// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"
	"strings"
)

// FileStore implements the [Store] interface using a directory of files, in
// which each key is encoded as a filename in the directory.
// The caller is responsible to ensure the directory path exists before
// using the store methods. The string is the absolute path to the directory.
type FileStore string

// List implements part of the [Store] interface.
func (s FileStore) List(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		des, err := os.ReadDir(string(s))
		if os.IsNotExist(err) {
			return // nothing to read
		} else if err != nil {
			yield("", err)
			return
		}

		// os.ReadDir reports entries already sorted, and the encoding preserves that.
		for _, de := range des {
			if de.IsDir() {
				continue
			}
			key, err := hex.DecodeString(de.Name())
			if err != nil {
				yield("", err)
				return
			}
			name := string(key)
			if !strings.HasPrefix(name, prefix) {
				continue
			} else if !yield(name, nil) {
				return
			}
		}
	}
}

// Load implements part of the [Store] interface.
func (s FileStore) Load(ctx context.Context, key string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(string(s), hex.EncodeToString([]byte(key))))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("key %q not found: %w", key, ErrKeyNotFound)
	}
	return data, err
}

// Store implements part of the [Store] interface.
func (s FileStore) Store(ctx context.Context, key string, value []byte) error {
	return os.WriteFile(filepath.Join(string(s), hex.EncodeToString([]byte(key))), value, 0600)
}

// Remove implements part of the [Store] interface.
func (s FileStore) Remove(ctx context.Context, key string) error {
	err := os.Remove(filepath.Join(string(s), hex.EncodeToString([]byte(key))))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Close implements part of the [Store] interface.
func (s FileStore) Close(context.Context) error { return nil }

// Clear implements part of the [Store] interface.
func (s FileStore) Clear(ctx context.Context) error {
	var errs []error
	for key, err := range s.List(ctx, "") {
		if err != nil {
			errs = append(errs, fmt.Errorf("list cache contents: %w", err))
			break
		}
		if err := s.Remove(ctx, key); err != nil {
			errs = append(errs, fmt.Errorf("discard cache key %q: %w", key, err))
		}
	}
	return errors.Join(errs...)
}
