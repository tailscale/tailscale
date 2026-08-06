// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonformat

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"time"
)

// arshal_time.go contains a verbatim copy of:
//   - appendTimeUnix
//   - parseTimeUnix
//   - appendDurationISO8601
//   - parseDurationISO8601
//   - (and any supporting functions)
//
// from encoding/json/v2/arshal_time.go@go1.27rc2.
// The only modification is that calling jsonwire.ParseUint was switched
// to jsonwireParseUint and that function verbatim copied here.

// appendDurationISO8601 appends an ISO 8601 duration with a restricted grammar,
// where leading and trailing zeroes and zero-value designators are omitted.
// It only uses hour, minute, and second designators since ISO 8601 defines
// those as being "accurate", while year, month, week, and day are "nominal".
func appendDurationISO8601(b []byte, d time.Duration) []byte {
	if d == 0 {
		return append(b, "PT0S"...)
	}
	b, n := mayAppendDurationSign(b, d)
	b = append(b, "PT"...)
	n, nsec := bits.Div64(0, n, 1e9)  // compute nsec field
	n, sec := bits.Div64(0, n, 60)    // compute sec field
	hour, min := bits.Div64(0, n, 60) // compute hour and min fields
	if hour > 0 {
		b = append(strconv.AppendUint(b, hour, 10), 'H')
	}
	if min > 0 {
		b = append(strconv.AppendUint(b, min, 10), 'M')
	}
	if sec > 0 || nsec > 0 {
		b = append(appendFracBase10(strconv.AppendUint(b, sec, 10), nsec, 1e9), 'S')
	}
	return b
}

// daysPerYear is the exact average number of days in a year according to
// the Gregorian calendar, which has an extra day each year that is
// a multiple of 4, unless it is evenly divisible by 100 but not by 400.
// This does not take into account leap seconds, which are not deterministic.
const daysPerYear = 365.2425

var errInaccurateDateUnits = errors.New("inaccurate year, month, week, or day units")

// parseDurationISO8601 parses a duration according to ISO 8601-1:2019,
// section 5.5.2.2 and 5.5.2.3 with the following restrictions or extensions:
//
//   - A leading minus sign is permitted for negative duration according
//     to ISO 8601-2:2019, section 4.4.1.9. We do not permit negative values
//     for each "time scale component", which is permitted by section 4.4.1.1,
//     but rarely supported by parsers.
//
//   - A leading plus sign is permitted (and ignored).
//     This is not required by ISO 8601, but not forbidden either.
//     There is some precedent for this as it is supported by the principle of
//     duration arithmetic as specified in ISO 8601-2-2019, section 14.1.
//     Of note, the JavaScript grammar for ISO 8601 permits a leading plus sign.
//
//   - A fractional value is only permitted for accurate units
//     (i.e., hour, minute, and seconds) in the last time component,
//     which is permissible by ISO 8601-1:2019, section 5.5.2.3.
//
//   - Both periods ('.') and commas (',') are supported as the separator
//     between the integer part and fraction part of a number,
//     as specified in ISO 8601-1:2019, section 3.2.6.
//     While ISO 8601 recommends comma as the default separator,
//     most formatters use a period.
//
//   - Leading zeros are ignored. This is not required by ISO 8601,
//     but also not forbidden by the standard. Many parsers support this.
//
//   - Lowercase designators are supported. This is not required by ISO 8601,
//     but also not forbidden by the standard. Many parsers support this.
//
// If the nominal units of year, month, week, or day are present,
// this produces a best-effort value and also reports [errInaccurateDateUnits].
//
// The accepted grammar is identical to JavaScript's Duration:
//
//	https://tc39.es/proposal-temporal/#prod-Duration
//
// We follow JavaScript's grammar as JSON itself is derived from JavaScript.
// The Temporal.Duration.toJSON method is guaranteed to produce an output
// that can be parsed by this function so long as arithmetic in JavaScript
// does not use a largestUnit value higher than "hours" (which is the default).
// Even if it does, this will do a best-effort parsing with inaccurate units,
// but report [errInaccurateDateUnits].
func parseDurationISO8601(b []byte) (time.Duration, error) {
	var invalid, overflow, inaccurate, sawFrac bool
	var sumNanos, n, co uint64

	// cutBytes is like [bytes.Cut], but uses either c0 or c1 as the separator.
	cutBytes := func(b []byte, c0, c1 byte) (prefix, suffix []byte, ok bool) {
		for i, c := range b {
			if c == c0 || c == c1 {
				return b[:i], b[i+1:], true
			}
		}
		return b, nil, false
	}

	// mayParseUnit attempts to parse another date or time number
	// identified by the desHi and desLo unit characters.
	// If the part is absent for current unit, it returns b as is.
	mayParseUnit := func(b []byte, desHi, desLo byte, unit time.Duration) []byte {
		number, suffix, ok := cutBytes(b, desHi, desLo)
		if !ok || sawFrac {
			return b // designator is not present or already saw fraction, which can only be in the last component
		}

		// Parse the number.
		// A fraction is allowed for the accurate units in the last part.
		whole, frac, ok := cutBytes(number, '.', ',')
		if ok {
			sawFrac = true
			invalid = invalid || len(frac) == len("") || unit > time.Hour
			if unit == time.Second {
				n, ok = parsePaddedBase10(frac, uint64(time.Second))
				invalid = invalid || !ok
			} else {
				f, err := strconv.ParseFloat("0."+string(frac), 64)
				invalid = invalid || err != nil || len(bytes.Trim(frac[len("."):], "0123456789")) > 0
				n = uint64(math.Round(f * float64(unit))) // never overflows since f is within [0..1]
			}
			sumNanos, co = bits.Add64(sumNanos, n, 0) // overflow if co > 0
			overflow = overflow || co > 0
		}
		for len(whole) > 1 && whole[0] == '0' {
			whole = whole[len("0"):] // trim leading zeros
		}
		n, ok := jsonwireParseUint(whole)          // overflow if !ok && MaxUint64
		hi, lo := bits.Mul64(n, uint64(unit))      // overflow if hi > 0
		sumNanos, co = bits.Add64(sumNanos, lo, 0) // overflow if co > 0
		invalid = invalid || (!ok && n != math.MaxUint64)
		overflow = overflow || (!ok && n == math.MaxUint64) || hi > 0 || co > 0
		inaccurate = inaccurate || unit > time.Hour
		return suffix
	}

	suffix, neg := consumeSign(b, true)
	prefix, suffix, okP := cutBytes(suffix, 'P', 'p')
	durDate, durTime, okT := cutBytes(suffix, 'T', 't')
	invalid = invalid || len(prefix) > 0 || !okP || (okT && len(durTime) == 0) || len(durDate)+len(durTime) == 0
	if len(durDate) > 0 { // nominal portion of the duration
		durDate = mayParseUnit(durDate, 'Y', 'y', time.Duration(daysPerYear*24*60*60*1e9))
		durDate = mayParseUnit(durDate, 'M', 'm', time.Duration(daysPerYear/12*24*60*60*1e9))
		durDate = mayParseUnit(durDate, 'W', 'w', time.Duration(7*24*60*60*1e9))
		durDate = mayParseUnit(durDate, 'D', 'd', time.Duration(24*60*60*1e9))
		invalid = invalid || len(durDate) > 0 // unknown elements
	}
	if len(durTime) > 0 { // accurate portion of the duration
		durTime = mayParseUnit(durTime, 'H', 'h', time.Duration(60*60*1e9))
		durTime = mayParseUnit(durTime, 'M', 'm', time.Duration(60*1e9))
		durTime = mayParseUnit(durTime, 'S', 's', time.Duration(1e9))
		invalid = invalid || len(durTime) > 0 // unknown elements
	}
	d := mayApplyDurationSign(sumNanos, neg)
	overflow = overflow || (neg != (d < 0) && d != 0) // overflows signed duration

	switch {
	case invalid:
		return 0, fmt.Errorf("invalid ISO 8601 duration %q: %w", b, strconv.ErrSyntax)
	case overflow:
		return 0, fmt.Errorf("invalid ISO 8601 duration %q: %w", b, strconv.ErrRange)
	case inaccurate:
		return d, fmt.Errorf("invalid ISO 8601 duration %q: %w", b, errInaccurateDateUnits)
	default:
		return d, nil
	}
}

// mayAppendDurationSign appends a negative sign if n is negative.
func mayAppendDurationSign(b []byte, d time.Duration) ([]byte, uint64) {
	if d < 0 {
		b = append(b, '-')
		d *= -1
	}
	return b, uint64(d)
}

// mayApplyDurationSign inverts n if neg is specified.
func mayApplyDurationSign(n uint64, neg bool) time.Duration {
	if neg {
		return -1 * time.Duration(n)
	} else {
		return +1 * time.Duration(n)
	}
}

// appendTimeUnix appends t formatted as a decimal fractional number,
// where pow10 is a power-of-10 used to scale up the number.
func appendTimeUnix(b []byte, t time.Time, pow10 uint64) []byte {
	sec, nsec := t.Unix(), int64(t.Nanosecond())
	if sec < 0 {
		b = append(b, '-')
		sec, nsec = negateSecNano(sec, nsec)
	}
	switch {
	case pow10 == 1e0: // fast case where units is in seconds
		b = strconv.AppendUint(b, uint64(sec), 10)
		return appendFracBase10(b, uint64(nsec), 1e9)
	case uint64(sec) < 1e9: // intermediate case where units is not seconds, but no overflow
		b = strconv.AppendUint(b, uint64(sec)*uint64(pow10)+uint64(uint64(nsec)/(1e9/pow10)), 10)
		return appendFracBase10(b, (uint64(nsec)*pow10)%1e9, 1e9)
	default: // slow case where units is not seconds and overflow would occur
		b = strconv.AppendUint(b, uint64(sec), 10)
		b = appendPaddedBase10(b, uint64(nsec)/(1e9/pow10), pow10)
		return appendFracBase10(b, (uint64(nsec)*pow10)%1e9, 1e9)
	}
}

// parseTimeUnix parses t formatted as a decimal fractional number,
// where pow10 is a power-of-10 used to scale down the number.
func parseTimeUnix(b []byte, pow10 uint64) (time.Time, error) {
	suffix, neg := consumeSign(b, false)                     // consume sign
	wholeBytes, fracBytes := bytesCutByte(suffix, '.', true) // consume whole and frac fields
	whole, okWhole := jsonwireParseUint(wholeBytes)          // parse whole field; may overflow
	frac, okFrac := parseFracBase10(fracBytes, 1e9/pow10)    // parse frac field
	var sec, nsec int64
	switch {
	case pow10 == 1e0: // fast case where units is in seconds
		sec = int64(whole) // check overflow later after negation
		nsec = int64(frac) // cannot overflow
	case okWhole: // intermediate case where units is not seconds, but no overflow
		sec = int64(whole / pow10)                     // check overflow later after negation
		nsec = int64((whole%pow10)*(1e9/pow10) + frac) // cannot overflow
	case !okWhole && whole == math.MaxUint64: // slow case where units is not seconds and overflow occurred
		width := int(math.Log10(float64(pow10)))                               // compute len(strconv.Itoa(pow10-1))
		whole, okWhole = jsonwireParseUint(wholeBytes[:len(wholeBytes)-width]) // parse the upper whole field
		mid, _ := parsePaddedBase10(wholeBytes[len(wholeBytes)-width:], pow10) // parse the lower whole field
		sec = int64(whole)                                                     // check overflow later after negation
		nsec = int64(mid*(1e9/pow10) + frac)                                   // cannot overflow
	}
	if neg {
		sec, nsec = negateSecNano(sec, nsec)
	}
	switch t := time.Unix(sec, nsec).UTC(); {
	case (!okWhole && whole != math.MaxUint64) || !okFrac:
		return time.Time{}, fmt.Errorf("invalid time %q: %w", b, strconv.ErrSyntax)
	case !okWhole || neg != (t.Unix() < 0):
		return time.Time{}, fmt.Errorf("invalid time %q: %w", b, strconv.ErrRange)
	default:
		return t, nil
	}
}

// negateSecNano negates a Unix timestamp, where nsec must be within [0, 1e9).
func negateSecNano(sec, nsec int64) (int64, int64) {
	sec = ^sec               // twos-complement negation (i.e., -1*sec + 1)
	nsec = -nsec + 1e9       // negate nsec and add 1e9 (which is the extra +1 from sec negation)
	sec += int64(nsec / 1e9) // handle possible overflow of nsec if it started as zero
	nsec %= 1e9              // ensure nsec stays within [0, 1e9)
	return sec, nsec
}

// appendFracBase10 appends the fraction of n/max10,
// where max10 is a power-of-10 that is larger than n.
func appendFracBase10(b []byte, n, max10 uint64) []byte {
	if n == 0 {
		return b
	}
	return bytes.TrimRight(appendPaddedBase10(append(b, '.'), n, max10), "0")
}

// parseFracBase10 parses the fraction of n/max10,
// where max10 is a power-of-10 that is larger than n.
func parseFracBase10(b []byte, max10 uint64) (n uint64, ok bool) {
	switch {
	case len(b) == 0:
		return 0, true
	case len(b) < len(".0") || b[0] != '.':
		return 0, false
	}
	return parsePaddedBase10(b[len("."):], max10)
}

// appendPaddedBase10 appends a zero-padded encoding of n,
// where max10 is a power-of-10 that is larger than n.
func appendPaddedBase10(b []byte, n, max10 uint64) []byte {
	if n < max10/10 {
		// Formatting of n is shorter than log10(max10),
		// so add max10/10 to ensure the length is equal to log10(max10).
		i := len(b)
		b = strconv.AppendUint(b, n+max10/10, 10)
		b[i]-- // subtract the addition of max10/10
		return b
	}
	return strconv.AppendUint(b, n, 10)
}

// parsePaddedBase10 parses b as the zero-padded encoding of n,
// where max10 is a power-of-10 that is larger than n.
// Truncated suffix is treated as implicit zeros.
// Extended suffix is ignored, but verified to contain only digits.
func parsePaddedBase10(b []byte, max10 uint64) (n uint64, ok bool) {
	pow10 := uint64(1)
	for pow10 < max10 {
		n *= 10
		if len(b) > 0 {
			if b[0] < '0' || '9' < b[0] {
				return n, false
			}
			n += uint64(b[0] - '0')
			b = b[1:]
		}
		pow10 *= 10
	}
	if len(b) > 0 && len(bytes.TrimRight(b, "0123456789")) > 0 {
		return n, false // trailing characters are not digits
	}
	return n, true
}

// consumeSign consumes an optional leading negative or positive sign.
func consumeSign(b []byte, allowPlus bool) ([]byte, bool) {
	if len(b) > 0 {
		if b[0] == '-' {
			return b[len("-"):], true
		} else if b[0] == '+' && allowPlus {
			return b[len("+"):], false
		}
	}
	return b, false
}

// bytesCutByte is similar to bytes.Cut(b, []byte{c}),
// except c may optionally be included as part of the suffix.
func bytesCutByte(b []byte, c byte, include bool) ([]byte, []byte) {
	if i := bytes.IndexByte(b, c); i >= 0 {
		if include {
			return b[:i], b[i:]
		}
		return b[:i], b[i+1:]
	}
	return b, nil
}

// jsonwireParseUint parses b as a decimal unsigned integer according to
// a strict subset of the JSON number grammar, returning the value if valid.
// It returns (0, false) if there is a syntax error and
// returns (math.MaxUint64, false) if there is an overflow.
func jsonwireParseUint(b []byte) (v uint64, ok bool) {
	const unsafeWidth = 20 // len(fmt.Sprint(uint64(math.MaxUint64)))
	var n int
	for ; len(b) > n && ('0' <= b[n] && b[n] <= '9'); n++ {
		v = 10*v + uint64(b[n]-'0')
	}
	switch {
	case n == 0 || len(b) != n || (b[0] == '0' && string(b) != "0"):
		return 0, false
	case n >= unsafeWidth && (b[0] != '1' || v < 1e19 || n > unsafeWidth):
		return math.MaxUint64, false
	}
	return v, true
}
