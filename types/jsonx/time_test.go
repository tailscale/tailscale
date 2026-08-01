// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonx

import (
	jsonv1 "encoding/json"
	"math/rand/v2"
	"testing"
	"time"

	jsonv2 "github.com/go-json-experiment/json"
)

// marshalWithFormatTag marshals v with the go-json-experiment module
// with support for `format:` json tags enabled, producing the encoding
// that these wrapper types must match byte for byte.
func marshalWithFormatTag(t *testing.T, v any) []byte {
	t.Helper()
	b, err := jsonv2.Marshal(v, jsonv2.ExperimentalSupportFormatTag(true))
	if err != nil {
		t.Fatalf("module marshal: %v", err)
	}
	return b
}

// interestingDurations returns fixed and random durations covering the
// interesting encoding cases.
func interestingDurations() []time.Duration {
	ds := []time.Duration{
		0,
		time.Nanosecond,
		-time.Nanosecond,
		time.Second,
		-time.Second,
		time.Second + 500*time.Millisecond,
		90*time.Second + 500*time.Millisecond,
		time.Hour + 2*time.Minute + 3*time.Second,
		-(time.Hour + 2*time.Minute + 3*time.Second + 4*time.Nanosecond),
		123456789 * time.Nanosecond,
		time.Duration(1<<63 - 1),
		-time.Duration(1<<63 - 1),
	}
	for range 100 {
		ds = append(ds, time.Duration(rand.Int64()-rand.Int64()))
	}
	return ds
}

// interestingTimes returns fixed and random times covering the
// interesting encoding cases.
func interestingTimes() []time.Time {
	ts := []time.Time{
		time.Unix(0, 0),
		time.Unix(1700000000, 0),
		time.Unix(1700000000, 500000000),
		time.Unix(1700000000, 123456789),
		time.Unix(1700000000, 1),
		time.Unix(-1, 500000000), // pre-epoch with fraction
		time.Unix(-1700000000, 0),
		time.Date(2262, 1, 1, 0, 0, 0, 999999999, time.UTC),
	}
	for range 100 {
		ts = append(ts, time.Unix(rand.Int64N(1<<33)-1<<32, rand.Int64N(1e9)))
	}
	return ts
}

func TestDurationTypesMatchFormatTags(t *testing.T) {
	for _, d := range interestingDurations() {
		type tagged struct {
			Nano    time.Duration `json:"n,format:nano"`
			Units   time.Duration `json:"u,format:units"`
			ISO8601 time.Duration `json:"i,format:iso8601"`
		}
		want := marshalWithFormatTag(t, tagged{d, d, d})

		type wrapped struct {
			Nano    DurationNano    `json:"n"`
			Units   DurationUnits   `json:"u"`
			ISO8601 DurationISO8601 `json:"i"`
		}
		w := wrapped{DurationNano(d), DurationUnits(d), DurationISO8601(d)}

		gotV1, err := jsonv1.Marshal(w)
		if err != nil {
			t.Fatalf("d=%v: v1 marshal: %v", d, err)
		}
		gotV2, err := jsonv2.Marshal(w)
		if err != nil {
			t.Fatalf("d=%v: v2 marshal: %v", d, err)
		}
		if string(gotV1) != string(want) {
			t.Errorf("d=%v: v1 mismatch:\n got %s\nwant %s", d, gotV1, want)
		}
		if string(gotV2) != string(want) {
			t.Errorf("d=%v: v2 mismatch:\n got %s\nwant %s", d, gotV2, want)
		}

		var back wrapped
		if err := jsonv1.Unmarshal(gotV1, &back); err != nil {
			t.Fatalf("d=%v: unmarshal: %v", d, err)
		}
		if back != w {
			t.Errorf("d=%v: round trip: got %+v, want %+v", d, back, w)
		}
	}
}

func TestTimeTypesMatchFormatTags(t *testing.T) {
	for _, tt := range interestingTimes() {
		type tagged struct {
			Unix     time.Time `json:"u,format:unix"`
			UnixNano time.Time `json:"n,format:unixnano"`
			RFC1123  time.Time `json:"r,format:RFC1123"`
		}
		want := marshalWithFormatTag(t, tagged{tt, tt, tt})

		type wrapped struct {
			Unix     TimeUnix     `json:"u"`
			UnixNano TimeUnixNano `json:"n"`
			RFC1123  TimeRFC1123  `json:"r"`
		}
		w := wrapped{TimeUnix{tt}, TimeUnixNano{tt}, TimeRFC1123{tt}}

		gotV1, err := jsonv1.Marshal(w)
		if err != nil {
			t.Fatalf("t=%v: v1 marshal: %v", tt, err)
		}
		gotV2, err := jsonv2.Marshal(w)
		if err != nil {
			t.Fatalf("t=%v: v2 marshal: %v", tt, err)
		}
		if string(gotV1) != string(want) {
			t.Errorf("t=%v: v1 mismatch:\n got %s\nwant %s", tt, gotV1, want)
		}
		if string(gotV2) != string(want) {
			t.Errorf("t=%v: v2 mismatch:\n got %s\nwant %s", tt, gotV2, want)
		}
	}
}

func TestTimeUnixRoundTrip(t *testing.T) {
	for _, tt := range interestingTimes() {
		w := TimeUnix{tt}
		b, err := jsonv1.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		var back TimeUnix
		if err := jsonv1.Unmarshal(b, &back); err != nil {
			t.Fatalf("t=%v: unmarshal %s: %v", tt, b, err)
		}
		if !back.Equal(tt) {
			t.Errorf("t=%v: round trip through %s: got %v", tt, b, back.Time)
		}
	}
}

func TestTimeUnixNanoRoundTrip(t *testing.T) {
	for _, tt := range interestingTimes() {
		w := TimeUnixNano{tt}
		b, err := jsonv1.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		var back TimeUnixNano
		if err := jsonv1.Unmarshal(b, &back); err != nil {
			t.Fatalf("t=%v: unmarshal %s: %v", tt, b, err)
		}
		if !back.Equal(tt) {
			t.Errorf("t=%v: round trip through %s: got %v", tt, b, back.Time)
		}
	}
}

func TestTimeRFC1123RoundTrip(t *testing.T) {
	// RFC 1123 has only second precision and needs a UTC zone name to
	// round trip exactly.
	tt := time.Date(2026, 8, 1, 12, 34, 56, 0, time.UTC)
	w := TimeRFC1123{tt}
	b, err := jsonv1.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var back TimeRFC1123
	if err := jsonv1.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	if !back.Equal(tt) {
		t.Errorf("round trip through %s: got %v, want %v", b, back.Time, tt)
	}
}

func TestLegacyFormsAccepted(t *testing.T) {
	// Times written by the legacy standard library encoding/json (which
	// ignored format tags) are RFC 3339 strings; durations are integer
	// nanosecond counts. Unmarshal must accept both.
	legacyTime, err := jsonv1.Marshal(time.Unix(1700000000, 500000000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	var tu TimeUnix
	if err := jsonv1.Unmarshal(legacyTime, &tu); err != nil {
		t.Fatalf("TimeUnix legacy %s: %v", legacyTime, err)
	}
	var tn TimeUnixNano
	if err := jsonv1.Unmarshal(legacyTime, &tn); err != nil {
		t.Fatalf("TimeUnixNano legacy %s: %v", legacyTime, err)
	}
	var tr TimeRFC1123
	if err := jsonv1.Unmarshal(legacyTime, &tr); err != nil {
		t.Fatalf("TimeRFC1123 legacy %s: %v", legacyTime, err)
	}
	want := time.Unix(1700000000, 500000000)
	for name, got := range map[string]time.Time{"TimeUnix": tu.Time, "TimeUnixNano": tn.Time, "TimeRFC1123": tr.Time} {
		if !got.Equal(want) {
			t.Errorf("%s legacy: got %v, want %v", name, got, want)
		}
	}

	var du DurationUnits
	if err := jsonv1.Unmarshal([]byte("90500000000"), &du); err != nil {
		t.Fatalf("DurationUnits legacy: %v", err)
	}
	if du.Duration() != 90*time.Second+500*time.Millisecond {
		t.Errorf("DurationUnits legacy: got %v", du)
	}
	var di DurationISO8601
	if err := jsonv1.Unmarshal([]byte("90500000000"), &di); err != nil {
		t.Fatalf("DurationISO8601 legacy: %v", err)
	}
	if di.Duration() != 90*time.Second+500*time.Millisecond {
		t.Errorf("DurationISO8601 legacy: got %v", di)
	}
}

func TestOmitZero(t *testing.T) {
	type S struct {
		D DurationNano `json:"d,omitzero"`
		T TimeUnix     `json:"t,omitzero"`
	}
	b, err := jsonv2.Marshal(S{})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "{}" {
		t.Errorf("omitzero: got %s, want {}", b)
	}
}
