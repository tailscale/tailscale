// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonformat

import (
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// DurationNano is a [time.Duration] that represents a duration as
// a JSON number of nanoseconds. If [json.StringifyNumbers] is specified,
// then it represents the duration as a JSON number within a JSON string.
//
// This format is what v1 [encoding/json] historically used for durations.
// It is not recommended that newly defined types represent durations
// using this format, as a standalone JSON number lacks context
// as to the units of the duration.
type DurationNano struct{ time.Duration }

func (d DurationNano) MarshalJSON() ([]byte, error) {
	return json.Marshal(d)
}

func (d DurationNano) MarshalJSONTo(enc *jsontext.Encoder) error {
	// Marshaling as an int64 directly allows us to properly handle
	// the [json.StringifyNumbers] option.
	return json.MarshalEncode(enc, int64(d.Duration))
}

func (d *DurationNano) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, d)
}

func (d *DurationNano) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	// Unmarshaling into an int64 directly allows us to properly handle
	// the [json.StringifyNumbers] option.
	return json.UnmarshalDecode(dec, (*int64)(&d.Duration))
}

// DurationUnits is a [time.Duration] that represents a duration as
// a JSON string using the format of [time.Duration.String].
//
// While this format is human-readable (e.g., "43m17.152s"),
// it is also highly specific to the Go ecosystem
// (and not used elsewhere in the industry).
type DurationUnits struct{ time.Duration }

func (d DurationUnits) MarshalJSON() ([]byte, error) {
	return json.Marshal(d)
}

func (d DurationUnits) MarshalJSONTo(enc *jsontext.Encoder) error {
	b := enc.AvailableBuffer()
	b = append(b, '"')
	b = append(b, d.Duration.String()...)
	b = append(b, '"')
	return enc.WriteValue(b)
}

func (d *DurationUnits) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, d)
}

func (d *DurationUnits) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	isNull := dec.PeekKind() == 'n'
	var s string
	if err := json.UnmarshalDecode(dec, &s); err != nil {
		return err
	}
	if isNull {
		d.Duration = 0
		return nil
	}
	var err error
	d.Duration, err = time.ParseDuration(s)
	return err
}

// DurationISO8601 is a [time.Duration] that represents a duration as
// a JSON string using a subset of the ISO 8601 format.
// In particular, it uses the exact grammar of ISO 8601 that JavaScript
// uses for its Temporal.Duration type.
//
// While this format is relatively novel in the Go ecosystem,
// the fact that JSON finds its heritage in JavaScript and that
// JavaScript has adopted ISO 8601 as the JSON representation for durations
// suggests that JavaScript's particular flavor of ISO 8601 may well become
// the de facto standard for representing durations across the industry.
type DurationISO8601 struct{ time.Duration }

func (d DurationISO8601) MarshalJSON() ([]byte, error) {
	return json.Marshal(d)
}

func (d DurationISO8601) MarshalJSONTo(enc *jsontext.Encoder) error {
	b := enc.AvailableBuffer()
	b = append(b, '"')
	b = appendDurationISO8601(b, d.Duration)
	b = append(b, '"')
	return enc.WriteValue(b)
}

func (d *DurationISO8601) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, d)
}

func (d *DurationISO8601) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	isNull := dec.PeekKind() == 'n'
	var s string
	if err := json.UnmarshalDecode(dec, &s); err != nil {
		return err
	}
	if isNull {
		d.Duration = 0
		return nil
	}
	var err error
	d.Duration, err = parseDurationISO8601([]byte(s))
	return err
}
