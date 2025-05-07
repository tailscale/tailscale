// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux || android

package systemd

func Ready()                {}
func Status(string, ...any) {}
