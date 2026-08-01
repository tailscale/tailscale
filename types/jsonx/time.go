// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonx

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-json-experiment/json/jsontext"
)

// This file provides wrapper types for time.Time and time.Duration that
// marshal to specific JSON wire formats.
//
// They exist to replace `format:` options in json struct tags (such as
// `json:",format:nano"`), which [github.com/go-json-experiment/json]
// used to support: Go 1.27's encoding/json rejects such tags outright,
// and the module moved its support behind a global experimental option
// slated for removal (see golang/go#71631). Unlike struct tags, which
// are interpreted only by the marshaler that happens to encode the
// struct, these types carry their wire format with them and produce
// identical bytes under both the standard library's encoding/json and
// the go-json-experiment module, on both Go 1.26 and Go 1.27.
//
// Each type marshals exactly as the module used to marshal the
// corresponding format tag. Where the standard library's legacy
// encoding/json produced a different encoding for the underlying type
// (because it ignored the format tag), Unmarshal also accepts that
// legacy form, so previously persisted data remains readable.

// DurationNano is a [time.Duration] that marshals as a JSON number of
// nanoseconds, like `format:nano` and like the standard library's
// encoding of time.Duration.
type DurationNano time.Duration

// Duration returns d as a [time.Duration].
func (d DurationNano) Duration() time.Duration { return time.Duration(d) }

func (d DurationNano) String() string { return time.Duration(d).String() }

func (d DurationNano) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, int64(d), 10), nil
}

func (d *DurationNano) UnmarshalJSON(b []byte) error {
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("jsonx.DurationNano: parsing %q: %w", b, err)
	}
	*d = DurationNano(n)
	return nil
}

func (d DurationNano) MarshalJSONTo(enc *jsontext.Encoder) error {
	b, _ := d.MarshalJSON()
	return enc.WriteValue(b)
}

func (d *DurationNano) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	b, err := dec.ReadValue()
	if err != nil {
		return err
	}
	return d.UnmarshalJSON(b)
}

// DurationUnits is a [time.Duration] that marshals as a JSON string in
// Go's duration syntax, such as "1h2m3.5s", like `format:units`.
//
// Unmarshal also accepts a JSON number of nanoseconds, which is how the
// standard library's legacy encoding/json encoded time.Duration.
type DurationUnits time.Duration

// Duration returns d as a [time.Duration].
func (d DurationUnits) Duration() time.Duration { return time.Duration(d) }

func (d DurationUnits) String() string { return time.Duration(d).String() }

func (d DurationUnits) MarshalJSON() ([]byte, error) {
	return strconv.AppendQuote(nil, time.Duration(d).String()), nil
}

func (d *DurationUnits) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] != '"' {
		// Legacy form: a JSON number of nanoseconds.
		n, err := strconv.ParseInt(string(b), 10, 64)
		if err != nil {
			return fmt.Errorf("jsonx.DurationUnits: parsing %q: %w", b, err)
		}
		*d = DurationUnits(n)
		return nil
	}
	s, err := strconv.Unquote(string(b))
	if err != nil {
		return fmt.Errorf("jsonx.DurationUnits: parsing %q: %w", b, err)
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("jsonx.DurationUnits: %w", err)
	}
	*d = DurationUnits(dur)
	return nil
}

func (d DurationUnits) MarshalJSONTo(enc *jsontext.Encoder) error {
	b, _ := d.MarshalJSON()
	return enc.WriteValue(b)
}

func (d *DurationUnits) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	b, err := dec.ReadValue()
	if err != nil {
		return err
	}
	return d.UnmarshalJSON(b)
}

// DurationISO8601 is a [time.Duration] that marshals as a JSON string
// containing an ISO 8601 duration, such as "PT1H2M3.5S", like
// `format:iso8601`. Only the accurate hour, minute, and second
// designators are used, matching the module's restricted grammar.
//
// Unmarshal also accepts a JSON number of nanoseconds, which is how the
// standard library's legacy encoding/json encoded time.Duration.
type DurationISO8601 time.Duration

// Duration returns d as a [time.Duration].
func (d DurationISO8601) Duration() time.Duration { return time.Duration(d) }

func (d DurationISO8601) String() string { return time.Duration(d).String() }

func (d DurationISO8601) MarshalJSON() ([]byte, error) {
	if d == 0 {
		return []byte(`"PT0S"`), nil
	}
	b := make([]byte, 0, 24)
	b = append(b, '"')
	n := uint64(d)
	if d < 0 {
		b = append(b, '-')
		n = uint64(-int64(d))
	}
	b = append(b, "PT"...)
	nsec := n % 1e9
	n /= 1e9
	sec := n % 60
	n /= 60
	min := n % 60
	hour := n / 60
	if hour > 0 {
		b = append(strconv.AppendUint(b, hour, 10), 'H')
	}
	if min > 0 {
		b = append(strconv.AppendUint(b, min, 10), 'M')
	}
	if sec > 0 || nsec > 0 {
		b = strconv.AppendUint(b, sec, 10)
		b = appendFrac(b, nsec, 1e9)
		b = append(b, 'S')
	}
	return append(b, '"'), nil
}

func (d *DurationISO8601) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] != '"' {
		// Legacy form: a JSON number of nanoseconds.
		n, err := strconv.ParseInt(string(b), 10, 64)
		if err != nil {
			return fmt.Errorf("jsonx.DurationISO8601: parsing %q: %w", b, err)
		}
		*d = DurationISO8601(n)
		return nil
	}
	s, err := strconv.Unquote(string(b))
	if err != nil {
		return fmt.Errorf("jsonx.DurationISO8601: parsing %q: %w", b, err)
	}
	dur, err := parseDurationISO8601(s)
	if err != nil {
		return fmt.Errorf("jsonx.DurationISO8601: parsing %q: %w", b, err)
	}
	*d = DurationISO8601(dur)
	return nil
}

func (d DurationISO8601) MarshalJSONTo(enc *jsontext.Encoder) error {
	b, _ := d.MarshalJSON()
	return enc.WriteValue(b)
}

func (d *DurationISO8601) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	b, err := dec.ReadValue()
	if err != nil {
		return err
	}
	return d.UnmarshalJSON(b)
}

// parseDurationISO8601 parses the restricted ISO 8601 duration grammar
// produced by DurationISO8601.MarshalJSON: an optional sign, then "PT",
// then optional hour, minute, and second fields, where only the second
// field may have a fractional component.
func parseDurationISO8601(s string) (time.Duration, error) {
	orig := s
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	rest, ok := strings.CutPrefix(s, "PT")
	if !ok {
		return 0, errors.New("missing PT prefix")
	}
	if rest == "" {
		return 0, errors.New("empty duration")
	}
	var total time.Duration
	seen := 0 // bitmask of seen designators, to enforce ordering
	for rest != "" {
		i := strings.IndexAny(rest, "HMS")
		if i < 0 {
			return 0, fmt.Errorf("missing unit designator in %q", orig)
		}
		num, unit := rest[:i], rest[i]
		rest = rest[i+1:]
		switch unit {
		case 'H':
			if seen >= 1 {
				return 0, errors.New("duplicate or misordered H")
			}
			seen = 1
			n, err := strconv.ParseUint(num, 10, 63)
			if err != nil {
				return 0, err
			}
			total += time.Duration(n) * time.Hour
		case 'M':
			if seen >= 2 {
				return 0, errors.New("duplicate or misordered M")
			}
			seen = 2
			n, err := strconv.ParseUint(num, 10, 63)
			if err != nil {
				return 0, err
			}
			total += time.Duration(n) * time.Minute
		case 'S':
			if seen >= 4 {
				return 0, errors.New("duplicate S")
			}
			seen = 4
			sec, frac, err := parseDecimal(num, 1e9)
			if err != nil {
				return 0, err
			}
			total += time.Duration(sec)*time.Second + time.Duration(frac)
		}
	}
	if neg {
		total = -total
	}
	return total, nil
}

// TimeUnix is a [time.Time] that marshals as a JSON number of seconds
// since the Unix epoch, with any sub-second component encoded as a
// decimal fraction with insignificant zeros omitted, like
// `format:unix`.
//
// Unmarshal also accepts an RFC 3339 JSON string, which is how the
// standard library's legacy encoding/json encoded time.Time.
type TimeUnix struct {
	time.Time
}

func (t TimeUnix) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, 24)
	sec, nsec := t.Unix(), uint64(t.Nanosecond())
	if sec < 0 && nsec > 0 {
		// Match the module's encoding of pre-epoch times: negate the
		// (sec, nsec) pair rather than emitting a negative second count
		// with a positive fraction.
		sec, nsec = -(sec + 1), 1e9-nsec
		b = append(b, '-')
	}
	b = strconv.AppendInt(b, sec, 10)
	b = appendFrac(b, nsec, 1e9)
	return b, nil
}

func (t *TimeUnix) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		// Legacy form: an RFC 3339 string.
		return t.Time.UnmarshalJSON(b)
	}
	s := string(b)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	sec, frac, err := parseDecimal(s, 1e9)
	if err != nil {
		return fmt.Errorf("jsonx.TimeUnix: parsing %q: %w", b, err)
	}
	nsec := int64(frac)
	if neg {
		sec, nsec = -sec, -nsec
	}
	t.Time = time.Unix(sec, nsec).UTC()
	return nil
}

func (t TimeUnix) MarshalJSONTo(enc *jsontext.Encoder) error {
	b, _ := t.MarshalJSON()
	return enc.WriteValue(b)
}

func (t *TimeUnix) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	b, err := dec.ReadValue()
	if err != nil {
		return err
	}
	return t.UnmarshalJSON(b)
}

// TimeUnixNano is a [time.Time] that marshals as a JSON number of
// nanoseconds since the Unix epoch, like `format:unixnano`.
//
// It can only represent times in the [time.Time.UnixNano] range
// (years 1678 to 2262).
//
// Unmarshal also accepts an RFC 3339 JSON string, which is how the
// standard library's legacy encoding/json encoded time.Time.
type TimeUnixNano struct {
	time.Time
}

func (t TimeUnixNano) MarshalJSON() ([]byte, error) {
	return strconv.AppendInt(nil, t.UnixNano(), 10), nil
}

func (t *TimeUnixNano) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		// Legacy form: an RFC 3339 string.
		return t.Time.UnmarshalJSON(b)
	}
	n, err := strconv.ParseInt(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("jsonx.TimeUnixNano: parsing %q: %w", b, err)
	}
	t.Time = time.Unix(0, n).UTC()
	return nil
}

func (t TimeUnixNano) MarshalJSONTo(enc *jsontext.Encoder) error {
	b, _ := t.MarshalJSON()
	return enc.WriteValue(b)
}

func (t *TimeUnixNano) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	b, err := dec.ReadValue()
	if err != nil {
		return err
	}
	return t.UnmarshalJSON(b)
}

// TimeRFC1123 is a [time.Time] that marshals as a JSON string in RFC
// 1123 format, such as "Mon, 02 Jan 2006 15:04:05 MST", like
// `format:RFC1123`.
//
// Unmarshal also accepts an RFC 3339 JSON string, which is how the
// standard library's legacy encoding/json encoded time.Time.
type TimeRFC1123 struct {
	time.Time
}

func (t TimeRFC1123) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(time.RFC1123)+2)
	b = append(b, '"')
	b = t.AppendFormat(b, time.RFC1123)
	return append(b, '"'), nil
}

func (t *TimeRFC1123) UnmarshalJSON(b []byte) error {
	s, err := strconv.Unquote(string(b))
	if err != nil {
		return fmt.Errorf("jsonx.TimeRFC1123: parsing %q: %w", b, err)
	}
	tt, err := time.Parse(time.RFC1123, s)
	if err != nil {
		// Legacy form: an RFC 3339 string.
		if tt3339, err3339 := time.Parse(time.RFC3339Nano, s); err3339 == nil {
			t.Time = tt3339
			return nil
		}
		return fmt.Errorf("jsonx.TimeRFC1123: %w", err)
	}
	t.Time = tt
	return nil
}

func (t TimeRFC1123) MarshalJSONTo(enc *jsontext.Encoder) error {
	b, _ := t.MarshalJSON()
	return enc.WriteValue(b)
}

func (t *TimeRFC1123) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	b, err := dec.ReadValue()
	if err != nil {
		return err
	}
	return t.UnmarshalJSON(b)
}

// appendFrac appends the fraction n/max10 as a decimal point followed
// by the significant fractional digits, omitting trailing zeros. It
// appends nothing if n is zero. max10 must be a power of 10 larger
// than n.
func appendFrac(b []byte, n, max10 uint64) []byte {
	if n == 0 {
		return b
	}
	b = append(b, '.')
	for max10 > 1 {
		max10 /= 10
		b = append(b, byte('0'+n/max10))
		n %= max10
	}
	return bytes.TrimRight(b, "0")
}

// parseDecimal parses a non-negative decimal number with an optional
// fractional component, returning the whole part and the fraction
// scaled to max10 (a power of 10). Fractional digits beyond the
// precision of max10 must be zero.
func parseDecimal(s string, max10 uint64) (whole int64, frac uint64, err error) {
	wholeStr, fracStr, hasFrac := strings.Cut(s, ".")
	whole, err = strconv.ParseInt(wholeStr, 10, 64)
	if err != nil {
		return 0, 0, err
	}
	if !hasFrac {
		return whole, 0, nil
	}
	if fracStr == "" {
		return 0, 0, errors.New("empty fraction")
	}
	scale := max10
	for _, c := range []byte(fracStr) {
		if c < '0' || c > '9' {
			return 0, 0, fmt.Errorf("invalid fraction digit %q", c)
		}
		if scale > 1 {
			scale /= 10
			frac += uint64(c-'0') * scale
		} else if c != '0' {
			return 0, 0, errors.New("fraction exceeds available precision")
		}
	}
	return whole, frac, nil
}
