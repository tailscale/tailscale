// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache

import (
	"context"
	"errors"
	"os"

	"tailscale.com/types/logger"
)

// NewStore creates [Store] for backing the netmapcache. If the [Store] already
// exists, open the existing [Store]. If [HookNewStore] is set (e.g. by
// feature/netmapcachesqlite), that implementation is used instead of the
// default [FileStore].
func NewStore(ctx context.Context, dir string, logf logger.Logf) (Store, error) {
	if f, ok := HookNewStore.GetOk(); ok {
		return f(ctx, dir, logf)
	}
	return FileStore(dir), nil
}

// OpenStore opens an existing [Store]. Returns nil, nil, if the store does not
// exist. If [HookOpenStore] is set (e.g. by feature/netmapcachesqlite), that
// implementation is used instead of the default [FileStore].
func OpenStore(ctx context.Context, dir string, logf logger.Logf) (Store, error) {
	if f, ok := HookOpenStore.GetOk(); ok {
		return f(ctx, dir, logf)
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return FileStore(dir), nil
}
