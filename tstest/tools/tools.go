// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file exists just so `go mod tidy` won't remove
// tool modules from our go.mod.

//go:build tools
// +build tools

package tools

import (
	_ "github.com/tailscale/mkctr"
	_ "honnef.co/go/tools/cmd/staticcheck"
)
