// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin && !ios

package resolver

import "tailscale.com/util/dnsname"

// negativeCache is a no-op on platforms without NXDOMAIN tracking.
type negativeCache struct{}

func (*negativeCache) queryGeneration() uint64 { return 0 }

func (*negativeCache) record(dnsname.FQDN, uint64) bool { return true }

// ClearNegativeCache is a no-op on this platform.
func (*Resolver) ClearNegativeCache() {}

// CheckCachedDNS always returns false on this platform.
func (*Resolver) CheckCachedDNS() bool { return false }
