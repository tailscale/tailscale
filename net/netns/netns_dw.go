// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || windows

package netns

func UseSocketMark() bool {
	return false
}
