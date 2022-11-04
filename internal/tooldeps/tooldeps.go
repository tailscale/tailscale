// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build for_go_mod_tidy_only

package tooldeps

import (
	_ "github.com/tailscale/depaware/depaware"
	_ "golang.org/x/tools/cmd/goimports"
)
