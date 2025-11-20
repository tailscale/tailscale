// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios && !ts_omit_tpm

package condregister

import _ "tailscale.com/feature/tpm"
