// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sockstatlog

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/net/sockstats"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
)

func TestResourceCleanup(t *testing.T) {
	if !sockstats.IsAvailable {
		t.Skip("sockstats not available")
	}
	tstest.ResourceCheck(t)
	td := t.TempDir()
	id, err := logid.NewPrivateID()
	if err != nil {
		t.Fatal(err)
	}
	lg, err := NewLogger(td, logger.Discard, id.Public(), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	lg.Write([]byte("hello"))
	lg.Shutdown(context.Background())
}

func TestDelta(t *testing.T) {
	tests := []struct {
		name      string
		a, b      *sockstats.SockStats
		wantStats map[sockstats.Label]deltaStat
	}{
		{
			name:      "nil a stat",
			a:         nil,
			b:         &sockstats.SockStats{},
			wantStats: nil,
		},
		{
			name:      "nil b stat",
			a:         &sockstats.SockStats{},
			b:         nil,
			wantStats: nil,
		},
		{
			name: "no change",
			a: &sockstats.SockStats{
				Stats: map[sockstats.Label]sockstats.SockStat{
					sockstats.LabelDERPHTTPClient: {
						TxBytes: 10,
					},
				},
			},
			b: &sockstats.SockStats{
				Stats: map[sockstats.Label]sockstats.SockStat{
					sockstats.LabelDERPHTTPClient: {
						TxBytes: 10,
					},
				},
			},
			wantStats: nil,
		},
		{
			name: "tx after empty stat",
			a:    &sockstats.SockStats{},
			b: &sockstats.SockStats{
				Stats: map[sockstats.Label]sockstats.SockStat{
					sockstats.LabelDERPHTTPClient: {
						TxBytes: 10,
					},
				},
			},
			wantStats: map[sockstats.Label]deltaStat{
				sockstats.LabelDERPHTTPClient: {10, 0},
			},
		},
		{
			name: "rx after non-empty stat",
			a: &sockstats.SockStats{
				Stats: map[sockstats.Label]sockstats.SockStat{
					sockstats.LabelDERPHTTPClient: {
						TxBytes: 10,
						RxBytes: 10,
					},
				},
			},
			b: &sockstats.SockStats{
				Stats: map[sockstats.Label]sockstats.SockStat{
					sockstats.LabelDERPHTTPClient: {
						TxBytes: 10,
						RxBytes: 30,
					},
				},
			},
			wantStats: map[sockstats.Label]deltaStat{
				sockstats.LabelDERPHTTPClient: {0, 20},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStats := delta(tt.a, tt.b)
			if !cmp.Equal(gotStats, tt.wantStats) {
				t.Errorf("gotStats = %v, want %v", gotStats, tt.wantStats)
			}
		})
	}
}
