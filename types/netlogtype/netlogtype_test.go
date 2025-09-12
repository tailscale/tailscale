// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_tailnetlock

package netlogtype

import (
	"encoding/json"
	"math"
	"net/netip"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"tailscale.com/util/must"
)

func TestMaxSize(t *testing.T) {
	maxAddr := netip.AddrFrom16([16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
	maxAddrPort := netip.AddrPortFrom(maxAddr, math.MaxUint16)
	cc := ConnectionCounts{
		// NOTE: These composite literals are deliberately unkeyed so that
		// added fields result in a build failure here.
		// Newly added fields should result in an update to both
		// MaxConnectionCountsJSONSize and MaxConnectionCountsCBORSize.
		Connection{math.MaxUint8, maxAddrPort, maxAddrPort},
		Counts{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64},
	}

	outJSON := must.Get(json.Marshal(cc))
	if string(outJSON) != maxJSONConnCounts {
		t.Errorf("JSON mismatch (-got +want):\n%s", cmp.Diff(string(outJSON), maxJSONConnCounts))
	}

	outCBOR := must.Get(cbor.Marshal(cc))
	maxCBORConnCountsAlt := "\xa7" + maxCBORConnCounts[1:len(maxCBORConnCounts)-1] // may use a definite encoding of map
	if string(outCBOR) != maxCBORConnCounts && string(outCBOR) != maxCBORConnCountsAlt {
		t.Errorf("CBOR mismatch (-got +want):\n%s", cmp.Diff(string(outCBOR), maxCBORConnCounts))
	}
}
