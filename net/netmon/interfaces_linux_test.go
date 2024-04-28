// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"tailscale.com/tstest"
)

// test the specific /proc/net/route path as found on Google Cloud Run instances
func TestGoogleCloudRunDefaultRouteInterface(t *testing.T) {
	dir := t.TempDir()
	tstest.Replace(t, &procNetRoutePath, filepath.Join(dir, "CloudRun"))
	buf := []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t8008FEA9\t00000000\t0001\t0\t0\t0\t01FFFFFF\t0\t0\t0\n" +
		"eth1\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n")
	err := os.WriteFile(procNetRoutePath, buf, 0644)
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
	tstest.Replace(t, &procNetRoutePath, filepath.Join(dir, "VeryLong"))
	f, err := os.Create(procNetRoutePath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"))
	if err != nil {
		t.Fatal(err)
	}

	for n := 0; n <= 900; n++ {
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

// test the specific /proc/net/route path as found on AWS App Runner instances
func TestAwsAppRunnerDefaultRouteInterface(t *testing.T) {
	dir := t.TempDir()
	tstest.Replace(t, &procNetRoutePath, filepath.Join(dir, "CloudRun"))
	buf := []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\tF9AFFEA9\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"*\tFEA9FEA9\t00000000\t0005\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n" +
		"ecs-eth0\t02AAFEA9\t01ACFEA9\t0007\t0\t0\t0\tFFFFFFFF\t0\t0\t0\n" +
		"ecs-eth0\t00ACFEA9\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n" +
		"eth0\t00AFFEA9\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n")
	err := os.WriteFile(procNetRoutePath, buf, 0644)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DefaultRouteInterface()
	if err != nil {
		t.Fatal(err)
	}

	if got != "eth0" {
		t.Fatalf("got %s, want eth0", got)
	}
}

func BenchmarkDefaultRouteInterface(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := DefaultRouteInterface(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRouteLinuxNetlink(t *testing.T) {
	d, err := defaultRouteFromNetlink()
	if errors.Is(err, fs.ErrPermission) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got: %+v", d)
}
