// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache

import (
	"context"
	"errors"
	"os"
)

// TODO(cmol): Add compiler flags when having more stores

// NewStore creates [Store] for backing the netmapcache. If the [Store] already
// exists, open the existing [Store].
func NewStore(_ context.Context, dir string) (Store, error) {
	return FileStore(dir), nil
}

// OpenStore opens an existing [Store]. Returns nil, nil, if the store does not
// exist.
func OpenStore(_ context.Context, dir string) (Store, error) {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return FileStore(dir), nil
}
