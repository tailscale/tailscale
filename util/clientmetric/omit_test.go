// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_clientmetrics

package clientmetric_test

import (
	"testing"

	"tailscale.com/util/clientmetric"
)

func TestOmittedGaugeFunc(t *testing.T) {
	m := clientmetric.NewGaugeFunc("omitted_gauge", func() int64 {
		t.Fatal("omitted metrics must not evaluate callbacks")
		return 1
	})
	m.DisableDeltas()
	if got := m.Value(); got != 0 {
		t.Errorf("Value() = %d, want 0", got)
	}
	if got := clientmetric.EncodeLogTailMetricsDelta(); got != "" {
		t.Errorf("EncodeLogTailMetricsDelta() = %q, want empty", got)
	}
}

// Policy metrics use Type and these constants even when client metrics are omitted.
var _ = []clientmetric.Type{clientmetric.TypeGauge, clientmetric.TypeCounter}
