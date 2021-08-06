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
	igd, err := NewTestIGD(t.Logf, TestIGDOptions{PMP: true, PCP: true, UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	c := newTestClient(t, igd)
	t.Logf("Listening on pxp=%v, upnp=%v", c.testPxPPort, c.testUPnPPort)
	defer c.Close()

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
		numPCPDiscoRecv:      1,
		numPMPPublicAddrRecv: 1,
	}
	if !reflect.DeepEqual(st, want) {
		t.Errorf("unexpected stats:\n got: %+v\nwant: %+v", st, want)
	}

	t.Logf("Probe: %+v", res)
	t.Logf("IGD stats: %+v", st)
	// TODO(bradfitz): finish
}

func TestPCPIntegration(t *testing.T) {
	igd, err := NewTestIGD(t.Logf, TestIGDOptions{PMP: false, PCP: true, UPnP: false})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	c := newTestClient(t, igd)
	defer c.Close()
	res, err := c.Probe(context.Background())
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if res.UPnP || res.PMP {
		t.Errorf("probe unexpectedly saw upnp or pmp: %+v", res)
	}
	if !res.PCP {
		t.Fatalf("probe did not see pcp: %+v", res)
	}

	external, err := c.createOrGetMapping(context.Background())
	if err != nil {
		t.Fatalf("failed to get mapping: %v", err)
	}
	if external.IsZero() {
		t.Errorf("got zero IP, expected non-zero")
	}
	if c.mapping == nil {
		t.Errorf("got nil mapping after successful createOrGetMapping")
	}
}
