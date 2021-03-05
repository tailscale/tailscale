// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import "testing"

func TestScrubbedGoroutineDump(t *testing.T) {
	t.Logf("Got:\n%s\n", scrubbedGoroutineDump())
}
