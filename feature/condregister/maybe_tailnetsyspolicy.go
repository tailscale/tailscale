// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Apple and Android GUI clients need more work to support tailnet system policy.
// Omit this feature until support is added for those platforms.
//go:build !ts_omit_syspolicy && !ts_macext && !android

package condregister

import (
	_ "tailscale.com/feature/tailnetsyspolicy"
)
