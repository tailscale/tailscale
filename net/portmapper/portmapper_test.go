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

func TestCreateOrGetMapping(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	c.SetLocalPort(1234)
	for i := 0; i < 2; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		ext, err := c.createOrGetMapping(context.Background())
		t.Logf("Got: %v, %v", ext, err)
	}
}

func TestClientProbe(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	for i := 0; i < 2; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		res, err := c.Probe(context.Background())
		t.Logf("Got: %+v, %v", res, err)
	}
}

func TestClientProbeThenMap(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	c.SetLocalPort(1234)
	res, err := c.Probe(context.Background())
	t.Logf("Probe: %+v, %v", res, err)
	ext, err := c.createOrGetMapping(context.Background())
	t.Logf("createOrGetMapping: %v, %v", ext, err)
}
