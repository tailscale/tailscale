// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

//go:generate go run tailscale.com/cmd/mkmanifest amd64 windows-manifest.xml manifest_windows_amd64.syso
//go:generate go run tailscale.com/cmd/mkmanifest 386 windows-manifest.xml manifest_windows_386.syso
//go:generate go run tailscale.com/cmd/mkmanifest arm64 windows-manifest.xml manifest_windows_arm64.syso
//go:generate go run tailscale.com/cmd/mkmanifest arm windows-manifest.xml manifest_windows_arm.syso
