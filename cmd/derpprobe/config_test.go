// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestConfig(t *testing.T) {
	var got config
	if err := yaml.Unmarshal([]byte(configYAML), &got); err != nil {
		t.Fatal(err)
	}
	want := config{
		DerpMap:     "https://derpmap.example.com/path",
		ListenAddr:  "*:8090",
		ProbeOnce:   true,
		Spread:      true,
		MapInterval: 1 * time.Second,
		Mesh: ProbeConfig{
			Interval: 2 * time.Second,
			Regions:  []string{"two"},
		},
		STUN: ProbeConfig{
			Interval: 3 * time.Second,
			Regions:  []string{"three"},
		},
		TLS: ProbeConfig{
			Interval: 4 * time.Second,
			Regions:  []string{"four"},
		},
		Bandwidth: BandwidthConfig{
			Interval: 5 * time.Second,
			Regions:  []string{"five"},
			Size:     12345,
		},
	}

	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatalf("Wrong config (-got +want):\n%s", diff)
	}
}

const configYAML = `
  derpmap: https://derpmap.example.com/path
  listenaddr: "*:8090"
  probeonce: true
  spread: true
  mapinterval: 1s
  mesh:
    interval: 2s
    regions: ["two"]
  stun:
    interval: 3s
    regions: ["three"]
  tls:
    interval: 4s
    regions: ["four"]
  bandwidth:
    interval: 5s
    size: 12345
    regions: ["five"]
`
