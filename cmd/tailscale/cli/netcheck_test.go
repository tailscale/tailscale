// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
)

func TestPrintReportShowsDNSMode(t *testing.T) {
	testCases := []struct {
		name           string
		dnsMode        string
		expectInOutput bool
	}{
		{"dns mode set", "direct", true},
		{"dns mode empty", "", false},
		{"dns mode other", "systemd-resolved", true},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable for parallel tests
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Setup a minimal DERP map for the report.
			mockDERPMap := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{1: {RegionID: 1, RegionName: "d1"}}}
			// Create a report with the test case's DNSMode.
			report := &netcheck.Report{Now: time.Unix(0, 0), DNSMode: tc.dnsMode}

			// Capture output by writing to a buffer.
			var outputBuf bytes.Buffer

			// Ensure human-readable output
			netcheckArgs.format = ""
			if err := printReport(&outputBuf, mockDERPMap, report); err != nil {
				t.Fatalf("printReport failed: %v", err)
			}

			output := outputBuf.String()
			if tc.expectInOutput {
				if !strings.Contains(output, "DNS Mode: "+ tc.dnsMode) {
					t.Errorf("expected DNS Mode %q in output, got: %q", tc.dnsMode, output)
				}
			} else {
				if strings.Contains(output, "DNS Mode:") {
					t.Errorf("did not expect DNS Mode line in output, got: %q", output)
				}
			}
		})
	}
}
