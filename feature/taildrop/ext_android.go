// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package taildrop

// on Android the caller will inject a ShareFileHelper–backed FileOps on Taildrop receipt,
// so do nothing here.
func setDefaultFileOps(e *Extension) {}
