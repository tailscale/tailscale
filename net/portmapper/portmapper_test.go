// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package portmapper

import (
	"context"
	"os"
	"reflect"
	"strconv"
	"testing"
	"time"

	"inet.af/netaddr"
	"tailscale.com/types/logger"
)

func TestCreateOrGetMapping(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	defer c.Close()
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
	defer c.Close()
	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(100 * time.Millisecond)
		}
		res, err := c.Probe(context.Background())
		t.Logf("Got(t=%dms): %+v, %v", i*100, res, err)
	}
}

func TestClientProbeThenMap(t *testing.T) {
	if v, _ := strconv.ParseBool(os.Getenv("HIT_NETWORK")); !v {
		t.Skip("skipping test without HIT_NETWORK=1")
	}
	c := NewClient(t.Logf, nil)
	defer c.Close()
	c.SetLocalPort(1234)
	res, err := c.Probe(context.Background())
	t.Logf("Probe: %+v, %v", res, err)
	ext, err := c.createOrGetMapping(context.Background())
	t.Logf("createOrGetMapping: %v, %v", ext, err)
}

func TestProbeIntegration(t *testing.T) {
	igd, err := NewTestIGD()
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	logf := t.Logf
	var c *Client
	c = NewClient(logger.WithPrefix(logf, "portmapper: "), func() {
		logf("portmapping changed.")
		logf("have mapping: %v", c.HaveMapping())
	})
	c.testPxPPort = igd.TestPxPPort()
	c.testUPnPPort = igd.TestUPnPPort()
	t.Logf("Listening on pxp=%v, upnp=%v", c.testPxPPort, c.testUPnPPort)
	c.SetGatewayLookupFunc(func() (gw, self netaddr.IP, ok bool) {
		return netaddr.IPv4(127, 0, 0, 1), netaddr.IPv4(1, 2, 3, 4), true
	})

	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !res.UPnP {
		t.Errorf("didn't detect UPnP")
	}
	st := igd.stats()
	want := igdCounters{
		numUPnPDiscoRecv:     1,
		numPMPRecv:           1,
		numPCPRecv:           1,
		numPMPPublicAddrRecv: 1,
	}
	if !reflect.DeepEqual(st, want) {
		t.Errorf("unexpected stats:\n got: %+v\nwant: %+v", st, want)
	}

	t.Logf("Probe: %+v", res)
	t.Logf("IGD stats: %+v", st)
	// TODO(bradfitz): finish
}
