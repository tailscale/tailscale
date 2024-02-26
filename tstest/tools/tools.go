// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// This file exists just so `go mod tidy` won't remove
// tool modules from our go.mod.

//go:build tools

package tools

import (
	_ "fybrik.io/crdoc"
	_ "github.com/tailscale/mkctr"
	_ "honnef.co/go/tools/cmd/staticcheck"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
