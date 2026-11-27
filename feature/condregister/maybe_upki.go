// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ((linux && !android) || freebsd || openbsd) && !ts_omit_upki

package condregister

import _ "tailscale.com/feature/upki"
