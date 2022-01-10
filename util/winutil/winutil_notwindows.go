// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !windows
// +build !windows

package winutil

const regBase = ``

func getPolicyString(name, defval string) string { return defval }

func getPolicyInteger(name string, defval uint64) uint64 { return defval }

func getRegString(name, defval string) string { return defval }

func getRegInteger(name string, defval uint64) uint64 { return defval }

func isSIDValidPrincipal(uid string) bool { return false }
