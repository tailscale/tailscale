// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsfallback

import "testing"

func TestGetDERPMap(t *testing.T) {
	dm := getDERPMap()
	if dm == nil {
		t.Fatal("nil")
	}
	if len(dm.Regions) == 0 {
		t.Fatal("no regions")
	}
}
