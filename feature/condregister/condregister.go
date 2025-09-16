// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The condregister package registers all conditional features guarded
// by build tags. It is one central package that callers can empty import
// to ensure all conditional features are registered.
package condregister

// Portmapper is special in that the CLI also needs to link it in,
// so it's pulled out into its own package, rather than using a maybe_*.go
// file in condregister.
import (
	_ "tailscale.com/feature/condregister/portmapper"
)
