// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_routecheck

package cli

import (
	"context"

	"tailscale.com/feature"
)

func routeCheckProbe(ctx context.Context) error {
	return feature.ErrUnavailable
}
