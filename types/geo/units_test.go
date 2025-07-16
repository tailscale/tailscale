// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package geo_test

import (
	"math"
	"strings"
	"testing"

	"tailscale.com/types/geo"
)

func TestDegrees(t *testing.T) {
	for _, tt := range []struct {
		name      string
		degs      geo.Degrees
		wantStr   string
		wantText  string
		wantPad   string
		wantRads  geo.Radians
		wantTurns geo.Turns
	}{
		{
			name:      "zero",
			degs:      0.0 * geo.Degree,
			wantStr:   "+0°",
			wantText:  "+0",
			wantPad:   "+000",
			wantRads:  0.0 * geo.Radian,
			wantTurns: 0 * geo.Turn,
		},
		{
			name:      "quarter-turn",
			degs:      90.0 * geo.Degree,
			wantStr:   "+90°",
			wantText:  "+90",
			wantPad:   "+090",
			wantRads:  0.5 * math.Pi * geo.Radian,
			wantTurns: 0.25 * geo.Turn,
		},
		{
			name:      "half-turn",
			degs:      180.0 * geo.Degree,
			wantStr:   "+180°",
			wantText:  "+180",
			wantPad:   "+180",
			wantRads:  1.0 * math.Pi * geo.Radian,
			wantTurns: 0.5 * geo.Turn,
		},
		{
			name:      "full-turn",
			degs:      360.0 * geo.Degree,
			wantStr:   "+360°",
			wantText:  "+360",
			wantPad:   "+360",
			wantRads:  2.0 * math.Pi * geo.Radian,
			wantTurns: 1.0 * geo.Turn,
		},
		{
			name:      "negative-zero",
			degs:      geo.MustParseDegrees("-0.0"),
			wantStr:   "-0°",
			wantText:  "-0",
			wantPad:   "-000",
			wantRads:  0 * geo.Radian * -1,
			wantTurns: 0 * geo.Turn * -1,
		},
		{
			name:      "small-degree",
			degs:      -1.2003 * geo.Degree,
			wantStr:   "-1.2003°",
			wantText:  "-1.2003",
			wantPad:   "-001.2003",
			wantRads:  -0.020949187011687936 * geo.Radian,
			wantTurns: -0.0033341666666666663 * geo.Turn,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.degs.String(); got != tt.wantStr {
				t.Errorf("String got %q, want %q", got, tt.wantStr)
			}

			d, err := geo.ParseDegrees(tt.wantStr)
			if err != nil {
				t.Fatalf("ParseDegrees err %q, want nil", err.Error())
			}
			if d != tt.degs {
				t.Errorf("ParseDegrees got %q, want %q", d, tt.degs)
			}

			b, err := tt.degs.AppendText(nil)
			if err != nil {
				t.Fatalf("AppendText err %q, want nil", err.Error())
			}
			if string(b) != tt.wantText {
				t.Errorf("AppendText got %q, want %q", b, tt.wantText)
			}

			b = tt.degs.AppendZeroPaddedText(nil, 3)
			if string(b) != tt.wantPad {
				t.Errorf("AppendZeroPaddedText got %q, want %q", b, tt.wantPad)
			}

			r := tt.degs.Radians()
			if r != tt.wantRads {
				t.Errorf("Radian got %v, want %v", r, tt.wantRads)
			}
			if d := r.Degrees(); d != tt.degs { // Roundtrip
				t.Errorf("Degrees got %v, want %v", d, tt.degs)
			}

			o := tt.degs.Turns()
			if o != tt.wantTurns {
				t.Errorf("Turns got %v, want %v", o, tt.wantTurns)
			}
		})
	}
}

func TestRadians(t *testing.T) {
	for _, tt := range []struct {
		name      string
		rads      geo.Radians
		wantStr   string
		wantText  string
		wantDegs  geo.Degrees
		wantTurns geo.Turns
	}{
		{
			name:      "zero",
			rads:      0.0 * geo.Radian,
			wantStr:   "0 rad",
			wantDegs:  0.0 * geo.Degree,
			wantTurns: 0 * geo.Turn,
		},
		{
			name:      "quarter-turn",
			rads:      0.5 * math.Pi * geo.Radian,
			wantStr:   "1.5707963267948966 rad",
			wantDegs:  90.0 * geo.Degree,
			wantTurns: 0.25 * geo.Turn,
		},
		{
			name:      "half-turn",
			rads:      1.0 * math.Pi * geo.Radian,
			wantStr:   "3.141592653589793 rad",
			wantDegs:  180.0 * geo.Degree,
			wantTurns: 0.5 * geo.Turn,
		},
		{
			name:      "full-turn",
			rads:      2.0 * math.Pi * geo.Radian,
			wantStr:   "6.283185307179586 rad",
			wantDegs:  360.0 * geo.Degree,
			wantTurns: 1.0 * geo.Turn,
		},
		{
			name:      "negative-zero",
			rads:      geo.MustParseRadians("-0"),
			wantStr:   "-0 rad",
			wantDegs:  0 * geo.Degree * -1,
			wantTurns: 0 * geo.Turn * -1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rads.String(); got != tt.wantStr {
				t.Errorf("String got %q, want %q", got, tt.wantStr)
			}

			r, err := geo.ParseRadians(tt.wantStr)
			if err != nil {
				t.Fatalf("ParseDegrees err %q, want nil", err.Error())
			}
			if r != tt.rads {
				t.Errorf("ParseDegrees got %q, want %q", r, tt.rads)
			}

			d := tt.rads.Degrees()
			if d != tt.wantDegs {
				t.Errorf("Degrees got %v, want %v", d, tt.wantDegs)
			}
			if r := d.Radians(); r != tt.rads { // Roundtrip
				t.Errorf("Radians got %v, want %v", r, tt.rads)
			}

			o := tt.rads.Turns()
			if o != tt.wantTurns {
				t.Errorf("Turns got %v, want %v", o, tt.wantTurns)
			}
		})
	}
}

func TestTurns(t *testing.T) {
	for _, tt := range []struct {
		name     string
		turns    geo.Turns
		wantStr  string
		wantText string
		wantDegs geo.Degrees
		wantRads geo.Radians
	}{
		{
			name:     "zero",
			turns:    0.0,
			wantStr:  "0",
			wantDegs: 0.0 * geo.Degree,
			wantRads: 0 * geo.Radian,
		},
		{
			name:     "quarter-turn",
			turns:    0.25,
			wantStr:  "0.25",
			wantDegs: 90.0 * geo.Degree,
			wantRads: 0.5 * math.Pi * geo.Radian,
		},
		{
			name:     "half-turn",
			turns:    0.5,
			wantStr:  "0.5",
			wantDegs: 180.0 * geo.Degree,
			wantRads: 1.0 * math.Pi * geo.Radian,
		},
		{
			name:     "full-turn",
			turns:    1.0,
			wantStr:  "1",
			wantDegs: 360.0 * geo.Degree,
			wantRads: 2.0 * math.Pi * geo.Radian,
		},
		{
			name:     "negative-zero",
			turns:    geo.Turns(math.Copysign(0, -1)),
			wantStr:  "-0",
			wantDegs: 0 * geo.Degree * -1,
			wantRads: 0 * geo.Radian * -1,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.turns.String(); got != tt.wantStr {
				t.Errorf("String got %q, want %q", got, tt.wantStr)
			}

			d := tt.turns.Degrees()
			if d != tt.wantDegs {
				t.Errorf("Degrees got %v, want %v", d, tt.wantDegs)
			}
			if o := d.Turns(); o != tt.turns { // Roundtrip
				t.Errorf("Turns got %v, want %v", o, tt.turns)
			}

			r := tt.turns.Radians()
			if r != tt.wantRads {
				t.Errorf("Turns got %v, want %v", r, tt.wantRads)
			}
		})
	}
}

func TestDistance(t *testing.T) {
	for _, tt := range []struct {
		name    string
		dist    geo.Distance
		wantStr string
	}{
		{
			name:    "zero",
			dist:    0.0 * geo.Meter,
			wantStr: "0m",
		},
		{
			name:    "random",
			dist:    4 * geo.Meter,
			wantStr: "4m",
		},
		{
			name:    "light-second",
			dist:    299_792_458 * geo.Meter,
			wantStr: "299792458m",
		},
		{
			name:    "planck-length",
			dist:    1.61625518e-35 * geo.Meter,
			wantStr: "0.0000000000000000000000000000000000161625518m",
		},
		{
			name:    "negative-zero",
			dist:    geo.Distance(math.Copysign(0, -1)),
			wantStr: "-0m",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.dist.String(); got != tt.wantStr {
				t.Errorf("String got %q, want %q", got, tt.wantStr)
			}

			r, err := geo.ParseDistance(tt.wantStr)
			if err != nil {
				t.Fatalf("ParseDegrees err %q, want nil", err.Error())
			}
			if r != tt.dist {
				t.Errorf("ParseDegrees got %q, want %q", r, tt.dist)
			}
		})
	}
}

func TestDistanceOnEarth(t *testing.T) {
	for _, tt := range []struct {
		name    string
		here    geo.Point
		there   geo.Point
		want    geo.Distance
		wantErr string
	}{
		{
			name:    "no-points",
			here:    geo.Point{},
			there:   geo.Point{},
			wantErr: "not a valid point",
		},
		{
			name:    "not-here",
			here:    geo.Point{},
			there:   geo.MakePoint(0, 0),
			wantErr: "not a valid point",
		},
		{
			name:    "not-there",
			here:    geo.MakePoint(0, 0),
			there:   geo.Point{},
			wantErr: "not a valid point",
		},
		{
			name:  "null-island",
			here:  geo.MakePoint(0, 0),
			there: geo.MakePoint(0, 0),
			want:  0 * geo.Meter,
		},
		{
			name:  "equator-to-south-pole",
			here:  geo.MakePoint(0, 0),
			there: geo.MakePoint(-90, 0),
			want:  geo.EarthMeanCircumference / 4,
		},
		{
			name:  "north-pole-to-south-pole",
			here:  geo.MakePoint(+90, 0),
			there: geo.MakePoint(-90, 0),
			want:  geo.EarthMeanCircumference / 2,
		},
		{
			name:  "meridian-to-antimeridian",
			here:  geo.MakePoint(0, 0),
			there: geo.MakePoint(0, -180),
			want:  geo.EarthMeanCircumference / 2,
		},
		{
			name:  "positive-to-negative-antimeridian",
			here:  geo.MakePoint(0, 180),
			there: geo.MakePoint(0, -180),
			want:  0 * geo.Meter,
		},
		{
			name:  "toronto-to-montreal",
			here:  geo.MakePoint(+43.70011, -79.41630),
			there: geo.MakePoint(+45.50884, -73.58781),
			want:  503_200 * geo.Meter,
		},
		{
			name:  "montreal-to-san-francisco",
			here:  geo.MakePoint(+45.50884, -73.58781),
			there: geo.MakePoint(+37.77493, -122.41942),
			want:  4_082_600 * geo.Meter,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.here.DistanceTo(tt.there)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("err %q, want nil", err)
			}
			if tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err %q, want %q", err, tt.wantErr)
			}

			approx := func(x, y geo.Distance) bool {
				return math.Abs(float64(x)-float64(y)) <= 10
			}
			if !approx(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}
