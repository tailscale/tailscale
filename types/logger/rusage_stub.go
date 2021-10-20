// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows || js
// +build windows js

package logger

func rusageMaxRSS() float64 {
	// TODO(apenwarr): Substitute Windows equivalent of Getrusage() here.
	return 0
}
