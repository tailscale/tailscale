// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestClientProber(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf)
	ctx := context.Background()
	prober := c.NewProber(ctx)
	time.Sleep(3 * time.Second)
	prober.Stop()
	res, err := prober.CurrentStatus()
	t.Logf("Got: %+v, %v", res, err)
}
