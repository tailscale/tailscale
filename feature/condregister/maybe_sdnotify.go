// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_sdnotify

package condregister

import _ "tailscale.com/feature/sdnotify"
