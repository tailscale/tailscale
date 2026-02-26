// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_webbrowser

package cli

import "github.com/toqueteos/webbrowser"

func init() {
	hookOpenURL.Set(webbrowser.Open)
}
