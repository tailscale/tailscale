// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_bird && (linux || darwin || freebsd || openbsd)

package condregister

import _ "tailscale.com/feature/bird"
