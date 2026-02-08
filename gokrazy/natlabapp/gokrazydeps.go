// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build for_go_mod_tidy_only

package gokrazydeps

import (
	_ "github.com/gokrazy/gokrazy"
	_ "github.com/gokrazy/gokrazy/cmd/dhcp"
	_ "github.com/gokrazy/serial-busybox"
	_ "github.com/tailscale/gokrazy-kernel"
	_ "tailscale.com/cmd/tailscale"
	_ "tailscale.com/cmd/tailscaled"
	_ "tailscale.com/cmd/tta"
)
