// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_tunlinkstats

package condregister

import _ "tailscale.com/feature/tunlinkstats"
