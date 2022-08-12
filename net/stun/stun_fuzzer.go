// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//go:build gofuzz
// +build gofuzz

package stun

func FuzzStunParser(data []byte) int {
	_, _, _ = ParseResponse(data)

	_, _ = ParseBindingRequest(data)
	return 1
}
