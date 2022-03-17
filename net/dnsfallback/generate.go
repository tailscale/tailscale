// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !hermetic
// +build !hermetic

package dnsfallback

//go:generate go run update-dns-fallbacks.go
