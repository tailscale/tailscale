// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import "github.com/peterbourgon/ff/v3/ffcli"

var maybeSystrayCmd func() *ffcli.Command // non-nil only on Linux, see configure_linux.go
