// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_exitnodehealth && !ts_omit_health && !ts_omit_useexitnode

package tsnet

import _ "tailscale.com/feature/exitnodehealth"
