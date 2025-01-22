// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import "github.com/peterbourgon/ff/v3/ffcli"

var (
	maybeSysExtCmd    func() *ffcli.Command // non-nil only on macOS, see configure_apple.go
	maybeVPNConfigCmd func() *ffcli.Command // non-nil only on macOS, see configure_apple.go
)
