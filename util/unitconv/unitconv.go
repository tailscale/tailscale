// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package unitconv implements string conversion functionality
// for unit prefixes such as those from the SI and IEC standards.
// It is catered towards printing of values for human consumption.
// Consequently it prints of reasonable precision proportional to
// the magnitude of the value itself.
package unitconv

import (
	"bytes"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/exp/constraints"
)

type numeric interface {
	constraints.Integer | constraints.Float
}

type prefixDivisor struct {
	prefix  string
	divisor float64
}

var prefixDivisorsSI = []prefixDivisor{
	{"Y", 1e+24},
	{"Z", 1e+21},
	{"E", 1e+18},
	{"P", 1e+15},
	{"T", 1e+12},
	{"G", 1e+9},
	{"M", 1e+6},
	{"k", 1e+3},
	{"", 1e0},
	{"m", 1e-3},
	{"µ", 1e-6},
	{"n", 1e-9},
	{"p", 1e-12},
	{"f", 1e-15},
	{"a", 1e-18},
	{"z", 1e-21},
	{"y", 1e-24},
}

var prefixDivisorsIEC = []prefixDivisor{
	{"Yi", 1 << 80},
	{"Zi", 1 << 70},
	{"Ei", 1 << 60},
	{"Pi", 1 << 50},
	{"Ti", 1 << 40},
	{"Gi", 1 << 30},
	{"Mi", 1 << 20},
	{"Ki", 1 << 10},
	{"", 1 << 0},
}

// appendFloat is similar to [strconv.AppendFloat] except it limits the output
// to a total number of digits rather than a fixed number of digits
// after the decimal point.
func appendFloat(b []byte, f float64, numDigits int) []byte {
	i := len(b)
	b = strconv.AppendFloat(b, f, 'f', numDigits, 64)
	j := bytes.IndexByte(b[i:], '.')
	if j >= numDigits {
		return b[:i+j]
	} else {
		return b[:i+numDigits+len(".")]
	}
}

func formatPrefixDivisor(f float64, numDigits int, unitSuffix string, prefixDivisors []prefixDivisor) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return strconv.FormatFloat(f, 'f', 0, 64)
	}
	var arr [16]byte
	b := arr[:0]
	if math.Signbit(f) {
		f = math.Abs(f)
		b = append(b, '-')
	}
	if f == 0 {
		return string(append(append(b, '0'), unitSuffix...))
	}
	unit := strings.TrimLeftFunc(unitSuffix, unicode.IsSpace)
	whitespace := unitSuffix[:len(unitSuffix)-len(unit)]
	for i, pd := range prefixDivisors {
		if f >= pd.divisor || i == len(prefixDivisors)-1 {
			fdiv := f / pd.divisor
			if float64(uint(fdiv))*pd.divisor == f {
				b = strconv.AppendUint(b, uint64(fdiv), 10) // exact integer
			} else {
				b = appendFloat(b, fdiv, numDigits)
			}
			b = append(append(append(b, whitespace...), pd.prefix...), unit...)
			break
		}
	}
	return string(b)
}

// FormatSI formats the number using a metric prefix (e.g. k, M, G, etc.)
// combined with the provided unit suffix. Any leading spaces in the unitSuffix
// are moved before the metric prefix.
//
// Example:
//
//	FormatSI(123, "P/s")     => "123P/s"
//	FormatSI(12345678, " W") => "12.3 MW"
//
// Exact precision and width of the output may change in the future.
func FormatSI[N numeric](v N, unitSuffix string) string {
	return formatPrefixDivisor(float64(v), len("999"), unitSuffix, prefixDivisorsSI)
}

// FormatIEC formats the number using a binary prefix (e.g. Ki, Mi, Gi, etc.)
// combined with the provided unit suffix. Any leading spaces in the unitSuffix
// are moved before the metric prefix.
//
// Example:
//
//	FormatIEC(123, "B")         => "123B"
//	FormatIEC(12345678, " B/s") => "11.77 MiB/s"
//
// Exact precision and width of the output may change in the future.
func FormatIEC[N numeric](v N, unitSuffix string) string {
	return formatPrefixDivisor(float64(v), len("1023"), unitSuffix, prefixDivisorsIEC)
}

// FormatDuration formats the duration with precision proportional to
// the magnitude of the duration. This differs from the [time.Duration.String]
// format in that it additionally supports year ('y') and day ('d') units,
// where a year is exactly 365.25 days and a day is exactly 24 hours.
//
// Examples:
//
//	12ns
//	5.12μs
//	832μs
//	8.14ms
//	512ms
//	1.3s
//	58s
//	5m23s
//	4h23m
//	4d16h
//	17y53d
func FormatDuration(d time.Duration) string {
	const timeDay = 24 * time.Hour
	const timeYear = 365*timeDay + timeDay/4
	var b []byte
	if d < 0 {
		d = -1 * max(d, math.MinInt64+1) // avoid negation overflow
		b = append(b, '-')
	}
	switch {
	case d < 1e3*time.Nanosecond:
		return string(append(b, d.Round(time.Nanosecond/1e0).String()...))
	case d < 1e1*time.Microsecond:
		return string(append(b, d.Round(time.Microsecond/1e2).String()...))
	case d < 1e2*time.Microsecond:
		return string(append(b, d.Round(time.Microsecond/1e1).String()...))
	case d < 1e3*time.Microsecond:
		return string(append(b, d.Round(time.Microsecond/1e0).String()...))
	case d < 1e1*time.Millisecond:
		return string(append(b, d.Round(time.Millisecond/1e2).String()...))
	case d < 1e2*time.Millisecond:
		return string(append(b, d.Round(time.Millisecond/1e1).String()...))
	case d < 1e3*time.Millisecond:
		return string(append(b, d.Round(time.Millisecond/1e0).String()...))
	case d < 1e1*time.Second:
		return string(append(b, d.Round(time.Second/1e1).String()...))
	case d < time.Minute:
		return string(append(b, d.Round(time.Second/1e0).String()...))
	default:
		// Invariant: d >= time.Minute at this point
		units := []struct {
			unit   byte
			period time.Duration
		}{{'y', timeYear}, {'d', timeDay}, {'h', time.Hour}, {'m', time.Minute}, {'s', time.Second}}
		for i, currUnit := range units {
			if d >= currUnit.period {
				nextUnit := units[i+1] // always safe since d >= time.Minute
				if d%currUnit.period%nextUnit.period >= nextUnit.period/2 {
					d = max(d, d+nextUnit.period/2) // round up in an overflow safe way
				}
				b = append(strconv.AppendUint(b, uint64(d/currUnit.period), 10), currUnit.unit)
				d = d % currUnit.period
				b = append(strconv.AppendUint(b, uint64(d/nextUnit.period), 10), nextUnit.unit)
				return string(b)
			}
		}
		panic("unreachable") // since d >= time.Minute
	}
}
