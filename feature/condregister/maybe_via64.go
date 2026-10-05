// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && !ts_omit_via64 && !ts_omit_osrouter && !ts_omit_netstack

package condregister

import _ "tailscale.com/feature/via64"
