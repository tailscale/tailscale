// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !ts_omit_sdnotify

package condregister

import _ "tailscale.com/feature/sdnotify"
