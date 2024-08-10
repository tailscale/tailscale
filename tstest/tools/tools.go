// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build tools

// This file exists just so `go mod tidy` won't remove
// tool modules from our go.mod.
package tools

import (
	_ "github.com/elastic/crd-ref-docs"
	_ "github.com/tailscale/mkctr"
	_ "honnef.co/go/tools/cmd/staticcheck"
	_ "sigs.k8s.io/controller-tools/cmd/controller-gen"
)
