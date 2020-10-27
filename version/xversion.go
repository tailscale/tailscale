// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !redo,xversion

package version

// Replaced at build time with the Go linker flag -X. See
// ../build_dist.sh for example usage, and version.go for field
// documentation.
var Long string = "<not set>"
var Short string = "<not set>"
var LONG = Long
var SHORT = Short
var GitCommit = ""
var ExtraGitCommit = ""
