// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"strings"
	"testing"
)

func TestMitigateSelf(t *testing.T) {
	output := strings.TrimSpace(runTestProg(t, "testprocessattributes", "MitigateSelf"))
	want := "OK"
	if output != want {
		t.Errorf("%s\n", strings.TrimPrefix(output, "error: "))
	}
}
