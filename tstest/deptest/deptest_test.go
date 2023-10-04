// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package deptest

import "testing"

func TestImports(t *testing.T) {
	ImportAliasCheck(t, "../../")
}
