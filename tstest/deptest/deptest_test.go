// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package deptest

import "testing"

func TestImports(t *testing.T) {
	ImportAliasCheck(t, "../../")
}
