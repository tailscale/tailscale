// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

//go:generate go run tailscale.com/cmd/mkmanifest amd64 windows-manifest.xml manifest_windows_amd64.syso
//go:generate go run tailscale.com/cmd/mkmanifest 386 windows-manifest.xml manifest_windows_386.syso
//go:generate go run tailscale.com/cmd/mkmanifest arm64 windows-manifest.xml manifest_windows_arm64.syso
