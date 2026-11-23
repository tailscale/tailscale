// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_netmapcachesqlite && !ts_omit_cachenetmap

// Package netmapcachesqlite provides a SQLite-backed implementation of the
// [netmapcache.Store] interface.
package netmapcachesqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"

	"tailscale.com/feature"
	"tailscale.com/ipn/ipnlocal/netmapcache"
	"tailscale.com/types/logger"

	_ "modernc.org/sqlite"
)

// schemaVersion holds the current version of the schema. Should the schema of
// an opened database be lower than schemaVersion, drop the cache and make a
// fresh cache.
const schemaVersion = 1

const logPrefix = "netmapcache: "

const schema = `
CREATE TABLE objects (
  content_hash BLOB PRIMARY KEY,
  data         BLOB NOT NULL
) STRICT;

CREATE TABLE items (
  name         TEXT PRIMARY KEY,
  content_hash BLOB NOT NULL
) STRICT;

CREATE TABLE schema_version (
  id      INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
) STRICT;

INSERT INTO schema_version (id, version) VALUES (1, ?);
`

func init() {
	if !feature.Register("netmapcachesqlite") {
		return
	}
	netmapcache.HookNewStore.Set(newStore)
	netmapcache.HookOpenStore.Set(openStore)
}

// SQLiteStore implements [netmapcache.Store] using a SQLite database.
type SQLiteStore struct {
	db   *sql.DB
	path string
}

// newStore creates or opens the SQLite store rooted at dir.
func newStore(ctx context.Context, dir string, logf logger.Logf) (netmapcache.Store, error) {
	dbPath := filepath.Join(dir, "netmap-cache.sqlite3")
	logf = logger.WithPrefix(logf, logPrefix)

	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		logf("cache does not exist, creating")
		db, createErr := createDatabase(ctx, dbPath)
		if createErr != nil {
			return nil, fmt.Errorf("error creating cache database: %w", createErr)
		}
		return &SQLiteStore{db: db, path: dbPath}, nil
	} else if err != nil {
		return nil, fmt.Errorf("cache db file error: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := verifySchema(ctx, db); err != nil {
		db.Close()
		logf("cache is stale: %v", err)
		var createErr error
		if db, createErr = createDatabase(ctx, dbPath); createErr != nil {
			return nil, fmt.Errorf("error creating cache database: %w", createErr)
		}
	}

	return &SQLiteStore{db: db, path: dbPath}, nil
}

// openStore opens the SQLite store at dir if it already exists, returning
// (nil, nil) if the database file is not present.
func openStore(ctx context.Context, dir string, logf logger.Logf) (netmapcache.Store, error) {
	dbPath := filepath.Join(dir, "netmap-cache.sqlite3")
	logf = logger.WithPrefix(logf, logPrefix)

	if _, err := os.Stat(dbPath); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	if err := verifySchema(ctx, db); err != nil {
		// We don't have a functioning cache, so remove it.
		db.Close()
		if removeErr := removeDatabase(dbPath); removeErr != nil {
			logf("could not remove stale database: %v", removeErr)
		}
		return nil, nil
	}

	return &SQLiteStore{db: db, path: dbPath}, nil
}

func verifySchema(ctx context.Context, db *sql.DB) error {
	var version int
	row := db.QueryRowContext(ctx, "SELECT version FROM schema_version;")
	if err := row.Scan(&version); err != nil {
		return fmt.Errorf("error querying for schema version: %w", err)
	} else if version != schemaVersion {
		return fmt.Errorf("current schema version %d, want %d", version, schemaVersion)
	}
	return nil
}

func createDatabase(ctx context.Context, path string) (*sql.DB, error) {
	if err := removeDatabase(path); err != nil {
		return nil, err
	}

	if writeErr := os.WriteFile(path, []byte{}, 0o600); writeErr != nil {
		return nil, fmt.Errorf("unable to create db file: %w", writeErr)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, schema, schemaVersion); err != nil {
		return nil, err
	}
	return db, nil
}

func removeDatabase(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unable to remove old cache: %w", err)
	}
	return nil
}

const listSQL = `SELECT name FROM items WHERE name LIKE ? || '%';`

// List implements [netmapcache.Store].
func (s *SQLiteStore) List(ctx context.Context, prefix string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		rows, err := s.db.QueryContext(ctx, listSQL, hex.EncodeToString([]byte(prefix)))
		if err != nil {
			yield("", err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var key string
			if err := rows.Scan(&key); err != nil {
				yield("", err)
				return
			}

			name, err := hex.DecodeString(key)
			if err != nil {
				yield("", fmt.Errorf("invalid hex in database: %w", err))
				return
			}
			if !yield(string(name), nil) {
				return
			}
		}

		if err := rows.Err(); err != nil {
			yield("", err)
		}
	}
}

const loadSQL = `
SELECT objects.data FROM objects
JOIN items ON items.content_hash = objects.content_hash
WHERE items.name = ?;`

// Load implements [netmapcache.Store].
func (s *SQLiteStore) Load(ctx context.Context, key string) ([]byte, error) {
	var buf []byte
	err := s.db.QueryRowContext(ctx, loadSQL,
		hex.EncodeToString([]byte(key)),
	).Scan(&buf)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("key %q not found: %w", key, netmapcache.ErrKeyNotFound)
	} else if err != nil {
		return nil, fmt.Errorf("unable to load item: %w", err)
	}
	return buf, nil
}

const upsertObjectSQL = `
INSERT INTO objects (content_hash, data) VALUES (?, ?)
ON CONFLICT (content_hash) DO UPDATE SET data = excluded.data;`

const upsertItemSQL = `
INSERT INTO items (name, content_hash) VALUES (?, ?)
ON CONFLICT (name) DO UPDATE SET content_hash = excluded.content_hash;`

// Store implements [netmapcache.Store].
func (s *SQLiteStore) Store(ctx context.Context, key string, value []byte) error {
	objectHash := sha256.Sum256(value)
	if _, err := s.db.ExecContext(ctx, upsertObjectSQL, objectHash[:], value); err != nil {
		return fmt.Errorf("unable to store item: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, upsertItemSQL, hex.EncodeToString([]byte(key)), objectHash[:]); err != nil {
		return fmt.Errorf("unable to store item: %w", err)
	}
	return nil
}

const deleteItemSQL = `DELETE FROM items WHERE name = ?;`

// deleteOrphanedObjectSQL removes an object by content_hash if it is no longer
// referenced by any item.
const deleteOrphanedObjectSQL = `
DELETE FROM objects WHERE content_hash = ? AND content_hash NOT IN (SELECT content_hash FROM items);`

const loadContentHashSQL = `SELECT content_hash FROM items WHERE name = ?;`

// Remove implements [netmapcache.Store].
func (s *SQLiteStore) Remove(ctx context.Context, key string) error {
	hexKey := hex.EncodeToString([]byte(key))

	// Look up the content_hash before deleting the item so we can clean up the
	// objects table afterward.
	var contentHash []byte
	err := s.db.QueryRowContext(ctx, loadContentHashSQL, hexKey).Scan(&contentHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // key does not exist, treat as success
	} else if err != nil {
		return fmt.Errorf("unable to remove item: %w", err)
	}

	if _, err := s.db.ExecContext(ctx, deleteItemSQL, hexKey); err != nil {
		return fmt.Errorf("unable to remove item: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, deleteOrphanedObjectSQL, contentHash); err != nil {
		return fmt.Errorf("unable to remove item: %w", err)
	}
	return nil
}

const clearSQL = `DELETE FROM items; DELETE FROM objects;`

// Clear implements [netmapcache.Store].
func (s *SQLiteStore) Clear(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, clearSQL)
	if err != nil {
		return fmt.Errorf("unable to clear cache: %w", err)
	}
	return nil
}

// Close implements [netmapcache.Store].
func (s *SQLiteStore) Close(ctx context.Context) error {
	if err := s.db.Close(); err != nil {
		return err
	}
	return nil
}
