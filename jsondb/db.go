// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package jsondb provides a trivial "database": a Go object saved to
// disk as JSON.
package jsondb

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"

	"tailscale.com/atomicfile"
)

// DB is a database backed by a JSON file.
type DB[T any] struct {
	// Data is the contents of the database.
	Data *T

	path string
}

// Open opens the database at path, creating it with a zero value if
// necessary.
func Open[T any](path string) (*DB[T], error) {
	bs, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &DB[T]{
			Data: new(T),
			path: path,
		}, nil
	} else if err != nil {
		return nil, err
	}

	var val T
	if err := json.Unmarshal(bs, &val); err != nil {
		return nil, err
	}

	return &DB[T]{
		Data: &val,
		path: path,
	}, nil
}

// Save writes db.Data back to disk.
func (db *DB[T]) Save() error {
	bs, err := json.Marshal(db.Data)
	if err != nil {
		return err
	}

	return atomicfile.WriteFile(db.path, bs, 0600)
}
