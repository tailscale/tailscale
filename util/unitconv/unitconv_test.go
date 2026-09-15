// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package unitconv

import (
	"math"
	"testing"
	"time"
)

func TestFormatSI(t *testing.T) {
	tests := []struct {
		in   float64
		unit string
		want string
	}{
		{-123456789123456789, "W", "-123PW"},
		{-12345678912345678, "W", "-12.3PW"},
		{-1234567891234567, "W", "-1.23PW"},
		{-123456789123456, "W", "-123TW"},
		{-12345678912345, "W", "-12.3TW"},
		{-1234567891234, "W", "-1.23TW"},
		{-123456789123, "W", "-123GW"},
		{-12345678912, "W", "-12.3GW"},
		{-1234567891, "W", "-1.23GW"},
		{-123456789, "W", "-123MW"},
		{-12345678, "W", "-12.3MW"},
		{-1234567, "W", "-1.23MW"},
		{-123456, "W", "-123kW"},
		{-12345, "W", "-12.3kW"},
		{-1234, "W", "-1.23kW"},
		{-123, "W", "-123W"},
		{-12, "W", "-12W"},
		{-1, "W", "-1W"},
		{0, "W", "0W"},
		{+123, "W", "123W"},
		{+123456, "W", "123kW"},
		{+123456789, "W", "123MW"},
		{+123456789123, "W", "123GW"},
		{+123456789123456, "W", "123TW"},
		{+123456789123456789, "W", "123PW"},
		{-1000000000000000000, " B", "-1 EB"},
		{-1000000000000000, " B", "-1 PB"},
		{-1000000000000, " B", "-1 TB"},
		{-1000000000, " B", "-1 GB"},
		{-1000000, " B", "-1 MB"},
		{-1000, " B", "-1 kB"},
		{0, " B", "0 B"},
		{+1000, " B", "1 kB"},
		{+1000000, " B", "1 MB"},
		{+1000000000, " B", "1 GB"},
		{+1000000000000, " B", "1 TB"},
		{+1000000000000000, " B", "1 PB"},
		{+1000000000000000000, " B", "1 EB"},
		{0.123456, "m", "123mm"},
		{0.0123456, "m", "12.3mm"},
		{0.00123456, "m", "1.23mm"},
		{0.000123456, "m", "123µm"},
		{0.0000123456, "m", "12.3µm"},
		{0.00000123456, "m", "1.23µm"},
		{0.000000123456, "m", "123nm"},
		{0.0000000123456, "m", "12.3nm"},
		{0.00000000123456, "m", "1.23nm"},
		{0.000000000123456, "m", "123pm"},
		{0.0000000000123456, "m", "12.3pm"},
		{0.00000000000123456, "m", "1.23pm"},
		{0.000000000000123456, "m", "123fm"},
		{0.0000000000000123456, "m", "12.3fm"},
		{0.00000000000000123456, "m", "1.23fm"},
		{0.000000000000000123456, "m", "123am"},
		{0.0000000000000000123456, "m", "12.3am"},
		{math.Nextafter(0, 1), "W", "0.00yW"},
		{math.Copysign(0, -1), "W", "-0W"},
		{math.Nextafter(1e0, math.Inf(-1)), "W", "1000mW"},
		{1e0, "W", "1W"},
		{math.Nextafter(1e0, math.Inf(+1)), "W", "1.00W"},
		{math.Nextafter(50e0, math.Inf(-1)), "W", "50.0W"},
		{50e0, "W", "50W"},
		{math.Nextafter(50e0, math.Inf(+1)), "W", "50.0W"},
		{math.Nextafter(1e3, math.Inf(-1)), "W", "1000W"},
		{1e3, "W", "1kW"},
		{math.Nextafter(1e3, math.Inf(+1)), "W", "1.00kW"},
		{math.Nextafter(1e6, math.Inf(-1)), "W", "1000kW"},
		{1e6, "W", "1MW"},
		{math.Nextafter(1e6, math.Inf(+1)), "W", "1.00MW"},
		{math.Nextafter(1e9, math.Inf(-1)), "W", "1000MW"},
		{1e9, "W", "1GW"},
		{math.Nextafter(1e9, math.Inf(+1)), "W", "1.00GW"},
		{math.Nextafter(500e9, math.Inf(-1)), "W", "500GW"},
		{500e9, "W", "500GW"},
		{math.Nextafter(500e9, math.Inf(+1)), "W", "500GW"},
		{math.Nextafter(1e12, math.Inf(-1)), "W", "1000GW"},
		{1e12, "W", "1TW"},
		{math.Nextafter(1e12, math.Inf(+1)), "W", "1.00TW"},
		{math.Nextafter(1e15, math.Inf(-1)), "W", "1000TW"},
		{1e15, "W", "1PW"},
		{math.Nextafter(1e15, math.Inf(+1)), "W", "1.00PW"},
		{math.Nextafter(1e18, math.Inf(-1)), "W", "1000PW"},
		{1e18, "W", "1EW"},
		{math.Nextafter(1e18, math.Inf(+1)), "W", "1.00EW"},
		{math.Nextafter(1e21, math.Inf(-1)), "W", "1000EW"},
		{1e21, "W", "1ZW"},
		{math.Nextafter(1e21, math.Inf(+1)), "W", "1.00ZW"},
		{math.Nextafter(1e24, math.Inf(-1)), "W", "1000ZW"},
		{1e24, "W", "1YW"},
		{math.Nextafter(1e24, math.Inf(+1)), "W", "1.00YW"},
		{math.Inf(-1), "W", "-Inf"},
		{math.Inf(+1), "W", "+Inf"},
		{math.NaN(), "W", "NaN"},
	}
	for _, tt := range tests {
		got := FormatSI(tt.in, tt.unit)
		if got != tt.want {
			t.Errorf("FormatSI(%v, %q) = %q, want %q", tt.in, tt.unit, got, tt.want)
		}
	}
}

func TestFormatIEC(t *testing.T) {
	tests := []struct {
		in   float64
		unit string
		want string
	}{
		{-123456789123456789, "B/s", "-109.6PiB/s"},
		{-12345678912345678, "B/s", "-10.96PiB/s"},
		{-1234567891234567, "B/s", "-1.096PiB/s"},
		{-123456789123456, "B/s", "-112.2TiB/s"},
		{-12345678912345, "B/s", "-11.22TiB/s"},
		{-1234567891234, "B/s", "-1.122TiB/s"},
		{-123456789123, "B/s", "-114.9GiB/s"},
		{-12345678912, "B/s", "-11.49GiB/s"},
		{-1234567891, "B/s", "-1.149GiB/s"},
		{-123456789, "B/s", "-117.7MiB/s"},
		{-12345678, "B/s", "-11.77MiB/s"},
		{-1234567, "B/s", "-1.177MiB/s"},
		{-123456, "B/s", "-120.5KiB/s"},
		{-12345, "B/s", "-12.05KiB/s"},
		{-1234, "B/s", "-1.205KiB/s"},
		{-123, "B/s", "-123B/s"},
		{-12, "B/s", "-12B/s"},
		{-1, "B/s", "-1B/s"},
		{0, "B/s", "0B/s"},
		{+123, "B/s", "123B/s"},
		{+123456, "B/s", "120.5KiB/s"},
		{+123456789, "B/s", "117.7MiB/s"},
		{+123456789123, "B/s", "114.9GiB/s"},
		{+123456789123456, "B/s", "112.2TiB/s"},
		{+123456789123456789, "B/s", "109.6PiB/s"},
		{-1000000000000000000, " B", "-888.1 PiB"},
		{-1000000000000000, " B", "-909.4 TiB"},
		{-1000000000000, " B", "-931.3 GiB"},
		{-1000000000, " B", "-953.6 MiB"},
		{-1000000, " B", "-976.5 KiB"},
		{-1000, " B", "-1000 B"},
		{0, " B", "0 B"},
		{+1000, " B", "1000 B"},
		{+1000000, " B", "976.5 KiB"},
		{+1000000000, " B", "953.6 MiB"},
		{+1000000000000, " B", "931.3 GiB"},
		{+1000000000000000, " B", "909.4 TiB"},
		{+1000000000000000000, " B", "888.1 PiB"},
		{math.Nextafter(0, 1), "B", "0.000B"},
		{math.Copysign(0, -1), "B", "-0B"},
		{math.Nextafter(1<<0, math.Inf(-1)), "B", "1.000B"},
		{1 << 0, "B", "1B"},
		{math.Nextafter(1<<0, math.Inf(+1)), "B", "1.000B"},
		{math.Nextafter(1<<10, math.Inf(-1)), "B", "1024B"},
		{1 << 10, "B", "1KiB"},
		{math.Nextafter(1<<10, math.Inf(+1)), "B", "1.000KiB"},
		{math.Nextafter(1<<20, math.Inf(-1)), "B", "1024KiB"},
		{1 << 20, "B", "1MiB"},
		{math.Nextafter(1<<20, math.Inf(+1)), "B", "1.000MiB"},
		{math.Nextafter(1<<30, math.Inf(-1)), "B", "1024MiB"},
		{1 << 30, "B", "1GiB"},
		{math.Nextafter(1<<30, math.Inf(+1)), "B", "1.000GiB"},
		{math.Nextafter(1<<40, math.Inf(-1)), "B", "1024GiB"},
		{1 << 40, "B", "1TiB"},
		{math.Nextafter(1<<40, math.Inf(+1)), "B", "1.000TiB"},
		{math.Nextafter(1<<50, math.Inf(-1)), "B", "1024TiB"},
		{1 << 50, "B", "1PiB"},
		{math.Nextafter(1<<50, math.Inf(+1)), "B", "1.000PiB"},
		{math.Nextafter(1<<60, math.Inf(-1)), "B", "1024PiB"},
		{1 << 60, "B", "1EiB"},
		{math.Nextafter(1<<60, math.Inf(+1)), "B", "1.000EiB"},
		{math.Nextafter(1<<70, math.Inf(-1)), "B", "1024EiB"},
		{1 << 70, "B", "1ZiB"},
		{math.Nextafter(1<<70, math.Inf(+1)), "B", "1.000ZiB"},
		{math.Nextafter(1<<80, math.Inf(-1)), "B", "1024ZiB"},
		{1 << 80, "B", "1YiB"},
		{math.Nextafter(1<<80, math.Inf(+1)), "B", "1.000YiB"},
		{math.Inf(-1), "B", "-Inf"},
		{math.Inf(+1), "B", "+Inf"},
		{math.NaN(), "B", "NaN"},
	}
	for _, tt := range tests {
		got := FormatIEC(tt.in, tt.unit)
		if got != tt.want {
			t.Errorf("FormatIEC(%v, %q) = %q, want %q", tt.in, tt.unit, got, tt.want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{-123456789123456789, "-3y333d"},
		{-123456789123456, "-1d10h"},
		{-123456789123, "-2m3s"},
		{-123456789, "-123ms"},
		{-123456, "-123µs"},
		{-123, "-123ns"},
		{0, "0s"},
		{123, "123ns"},
		{123456, "123µs"},
		{123456789, "123ms"},
		{123456789123, "2m3s"},
		{123456789123456, "1d10h"},
		{123456789123456789, "3y333d"},
		{math.MinInt64, "-292y98d"},
		{math.MaxInt64, "292y98d"},
		{time.Minute - 1, "1m0s"},
		{time.Minute, "1m0s"},
		{time.Hour - 1, "60m0s"},
		{time.Hour, "1h0m"},
		{24*time.Hour - 1, "24h0m"},
		{24 * time.Hour, "1d0h"},
		{365 * 24 * time.Hour, "365d0h"},
		{365*24*time.Hour + 6*time.Hour - 1, "365d6h"},
		{365*24*time.Hour + 6*time.Hour, "1y0d"},
	}
	for _, tt := range tests {
		got := FormatDuration(tt.in)
		if got != tt.want {
			t.Errorf("FormatDuration(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
