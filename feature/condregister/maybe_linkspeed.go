// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && !android && !ts_omit_linkspeed

package condregister

import _ "tailscale.com/feature/linkspeed"
