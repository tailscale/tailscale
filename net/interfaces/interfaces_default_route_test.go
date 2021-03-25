// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,!redo

package interfaces

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRouteInterface(t *testing.T) {
	// tests /proc/net/route on the local system, cannot make an assertion about
	// the correct interface name, but good as a sanity check.
	v, err := DefaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got %q", v)
}

// test the specific /proc/net/route path as found on Google Cloud Run instances
func TestGoogleCloudRunDefaultRouteInterface(t *testing.T) {
	dir := t.TempDir()
	savedProcNetRoutePath := procNetRoutePath
	defer func() { procNetRoutePath = savedProcNetRoutePath }()
	procNetRoutePath = filepath.Join(dir, "CloudRun")
	buf := []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t8008FEA9\t00000000\t0001\t0\t0\t0\t01FFFFFF\t0\t0\t0\n" +
		"eth1\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n")
	err := ioutil.WriteFile(procNetRoutePath, buf, 0644)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DefaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}

	if got != "eth1" {
		t.Fatalf("got %s, want eth1", got)
	}
}

// we read chunks of /proc/net/route at a time, test that files longer than the chunk
// size can be handled.
func TestExtremelyLongProcNetRoute(t *testing.T) {
	dir := t.TempDir()
	savedProcNetRoutePath := procNetRoutePath
	defer func() { procNetRoutePath = savedProcNetRoutePath }()
	procNetRoutePath = filepath.Join(dir, "VeryLong")
	f, err := os.Create(procNetRoutePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"))
	if err != nil {
		t.Fatal(err)
	}

	for n := 0; n <= 1000; n++ {
		line := fmt.Sprintf("eth%d\t8008FEA9\t00000000\t0001\t0\t0\t0\t01FFFFFF\t0\t0\t0\n", n)
		_, err := f.Write([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = f.Write([]byte("tokenring1\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := DefaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}

	if got != "tokenring1" {
		t.Fatalf("got %q, want tokenring1", got)
	}
}
