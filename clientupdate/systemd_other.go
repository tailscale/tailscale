// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package clientupdate

import (
	"context"
	"errors"
)

func restartSystemdUnit(ctx context.Context) error {
	return errors.ErrUnsupported
}
