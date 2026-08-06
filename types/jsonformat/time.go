// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonformat

import (
	"reflect"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
)

// TimeUnix is a [time.Time] that represents time as a JSON number
// of seconds since the Unix epoch. If [json.StringifyNumbers] is specified,
// then it represents the time as a JSON number within a JSON string.
//
// Note that this format preserves the fractional number of seconds.
// To encode just the seconds as an integer, call [time.Time.Round]
// prior to JSON marshaling.
type TimeUnix struct{ time.Time }

func (t TimeUnix) MarshalJSON() ([]byte, error) {
	return json.Marshal(t)
}

func (t TimeUnix) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalTimeUnixTo(enc, t.Time, 1e0)
}

func (t *TimeUnix) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, t)
}

func (t *TimeUnix) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalTimeUnixFrom(dec, &t.Time, 1e0)
}

// TimeUnixNano is a [time.Time] that represents time as a JSON number
// of nanoseconds since the Unix epoch. If [json.StringifyNumbers] is specified,
// then it represents the time as a JSON number within a JSON string.
type TimeUnixNano struct{ time.Time }

func (t TimeUnixNano) MarshalJSON() ([]byte, error) {
	return json.Marshal(t)
}

func (t TimeUnixNano) MarshalJSONTo(enc *jsontext.Encoder) error {
	return marshalTimeUnixTo(enc, t.Time, 1e9)
}

func (t *TimeUnixNano) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, t)
}

func (t *TimeUnixNano) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	return unmarshalTimeUnixFrom(dec, &t.Time, 1e9)
}

func marshalTimeUnixTo(enc *jsontext.Encoder, t time.Time, pow10 uint64) error {
	stringify, _ := json.GetOption(enc.Options(), json.StringifyNumbers)
	b := enc.AvailableBuffer()
	if stringify {
		b = append(b, '"')
	}
	b = appendTimeUnix(b, t, pow10)
	if stringify {
		b = append(b, '"')
	}
	return enc.WriteValue(b)
}

func unmarshalTimeUnixFrom(dec *jsontext.Decoder, t *time.Time, pow10 uint64) error {
	stringify, _ := json.GetOption(dec.Options(), json.StringifyNumbers)
	switch tok, err := dec.ReadToken(); {
	case err != nil:
		return err
	case tok.Kind() == 'n':
		*t = time.Time{}
		return nil
	case tok.Kind() == '"' && stringify,
		tok.Kind() == '0' && !stringify:
		t2, err := parseTimeUnix([]byte(tok.String()), pow10)
		if err != nil {
			return err
		}
		*t = t2
		return nil
	default:
		return &json.SemanticError{JSONKind: tok.Kind(), GoType: reflect.TypeFor[time.Time]()}
	}
}

// TimeRFC1123 is a [time.Time] that represents time as a JSON string
// formatted using [time.RFC1123].
type TimeRFC1123 struct{ time.Time }

func (t TimeRFC1123) MarshalJSON() ([]byte, error) {
	return json.Marshal(t)
}

func (t TimeRFC1123) MarshalJSONTo(enc *jsontext.Encoder) error {
	b := enc.AvailableBuffer()
	b = append(b, '"')
	b = t.Time.AppendFormat(b, time.RFC1123)
	b = append(b, '"')
	return enc.WriteValue(b)
}

func (t *TimeRFC1123) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, t)
}

func (t *TimeRFC1123) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	switch tok, err := dec.ReadToken(); {
	case err != nil:
		return err
	case tok.Kind() == 'n':
		t.Time = time.Time{}
		return nil
	case tok.Kind() == '"':
		t2, err := time.Parse(time.RFC1123, tok.String())
		if err != nil {
			return err
		}
		t.Time = t2
		return nil
	default:
		return &json.SemanticError{JSONKind: tok.Kind(), GoType: reflect.TypeFor[time.Time]()}
	}
}
