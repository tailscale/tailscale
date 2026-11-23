// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmapcache

import (
	"context"

	"tailscale.com/feature"
	"tailscale.com/types/logger"
)

// HookNewStore if set, overrides the default [FileStore]-based [NewStore]
// implementation. The hook receives the same dir argument as [NewStore] and
// must create the store if it does not already exist, as [NewStore] does.
var HookNewStore feature.Hook[func(ctx context.Context, dir string, logf logger.Logf) (Store, error)]

// HookOpenStore if set, overrides the default [FileStore]-based [OpenStore]
// implementation. The hook receives the same dir argument as [OpenStore] and
// must return (nil, nil) if no store exists at that path, as [OpenStore] does.
var HookOpenStore feature.Hook[func(ctx context.Context, dir string, logf logger.Logf) (Store, error)]
