// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !darwin,!windows

package resolver

func networkIsDown(err error) bool        { return false }
func networkIsUnreachable(err error) bool { return false }
