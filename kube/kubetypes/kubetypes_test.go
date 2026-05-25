// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package kubetypes

import "testing"

func TestContainer(t *testing.T) {
	c := Container{}
	if c.Name != "" {
		t.Error("new Container should have empty Name")
	}
}

func TestPodReady(t *testing.T) {
	ready := PodReady("True")
	if ready != "True" {
		t.Errorf("PodReady = %q, want %q", ready, "True")
	}
}
