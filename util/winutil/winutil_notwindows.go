// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package winutil

const RegBase = ``

// GetRegString looks up a registry path in our local machine path, or returns
// the given default if it can't.
//
// This function will only work on GOOS=windows. Trying to run it on any other
// OS will always return the default value.
func GetRegString(name, defval string) string { return defval }
