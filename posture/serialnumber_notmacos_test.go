// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Build on Windows, Linux and *BSD

//go:build windows || (linux && !android) || freebsd || openbsd || dragonfly || netbsd

package posture

import (
	"fmt"
	"testing"

	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/policyclient"
)

func TestGetSerialNumberNotMac(t *testing.T) {
	// This test is intentionally skipped as it will
	// require root on Linux to get access to the serials.
	// The test case is intended for local testing.
	// Comment out skip for local testing.
	t.Skip()

	sns, err := GetSerialNumbers(policyclient.NoPolicyClient{}, logger.Discard)
	if err != nil {
		t.Fatalf("failed to get serial number: %s", err)
	}

	if len(sns) == 0 {
		t.Fatalf("expected at least one serial number, got %v", sns)
	}

	if len(sns[0]) <= 0 {
		t.Errorf("expected a serial number with more than zero characters, got %s", sns[0])
	}

	fmt.Printf("serials: %v\n", sns)
}
