// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android || js

package cloudinfo

import (
	"context"
	"net/netip"

	"tailscale.com/types/logger"
)

// CloudInfo is not available in mobile and JS targets.
type CloudInfo struct{}

// New construct a no-op CloudInfo stub.
func New(_ logger.Logf) *CloudInfo {
	return &CloudInfo{}
}

// GetPublicIPs always returns nil slice and error.
func (ci *CloudInfo) GetPublicIPs(_ context.Context) ([]netip.Addr, error) {
	return nil, nil
}
