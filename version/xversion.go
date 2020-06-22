// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !redo,xversion

package version

// Replaced at build time with the Go linker flag -X.
var LONG string = "<not set>"
var SHORT string = "<not set>"
