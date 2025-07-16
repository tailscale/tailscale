// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package geo

import (
	"math"
	"strconv"
	"strings"
	"unicode"
)

const (
	Degree Degrees  = 1
	Radian Radians  = 1
	Turn   Turns    = 1
	Meter  Distance = 1
)

// Degrees represents a latitude or longitude, in decimal degrees.
type Degrees float64

// ParseDegrees parses s as decimal degrees.
func ParseDegrees(s string) (Degrees, error) {
	s = strings.TrimSuffix(s, "°")
	f, err := strconv.ParseFloat(s, 64)
	return Degrees(f), err
}

// MustParseDegrees parses s as decimal degrees, but panics on error.
func MustParseDegrees(s string) Degrees {
	d, err := ParseDegrees(s)
	if err != nil {
		panic(err)
	}
	return d
}

// String implements the [Stringer] interface. The output is formatted in
// decimal degrees, prefixed by either the appropriate + or - sign, and suffixed
// by a ° degree symbol.
func (d Degrees) String() string {
	b, _ := d.AppendText(nil)
	b = append(b, []byte("°")...)
	return string(b)
}

// AppendText implements [encoding.TextAppender]. The output is formatted in
// decimal degrees, prefixed by either the appropriate + or - sign.
func (d Degrees) AppendText(b []byte) ([]byte, error) {
	b = d.AppendZeroPaddedText(b, 0)
	return b, nil
}

// AppendZeroPaddedText appends d formatted as decimal degrees to b. The number of
// integer digits will be zero-padded to nint.
func (d Degrees) AppendZeroPaddedText(b []byte, nint int) []byte {
	n := float64(d)

	if math.IsInf(n, 0) || math.IsNaN(n) {
		return strconv.AppendFloat(b, n, 'f', -1, 64)
	}

	sign := byte('+')
	if math.Signbit(n) {
		sign = '-'
		n = -n
	}
	b = append(b, sign)

	pad := nint - 1
	for nn := n / 10; nn >= 1 && pad > 0; nn /= 10 {
		pad--
	}
	for range pad {
		b = append(b, '0')
	}
	return strconv.AppendFloat(b, n, 'f', -1, 64)
}

// Radians converts d into radians.
func (d Degrees) Radians() Radians {
	return Radians(d * math.Pi / 180.0)
}

// Turns converts d into a number of turns.
func (d Degrees) Turns() Turns {
	return Turns(d / 360.0)
}

// Radians represents a latitude or longitude, in radians.
type Radians float64

// ParseRadians parses s as radians.
func ParseRadians(s string) (Radians, error) {
	s = strings.TrimSuffix(s, "rad")
	s = strings.TrimRightFunc(s, unicode.IsSpace)
	f, err := strconv.ParseFloat(s, 64)
	return Radians(f), err
}

// MustParseRadians parses s as radians, but panics on error.
func MustParseRadians(s string) Radians {
	r, err := ParseRadians(s)
	if err != nil {
		panic(err)
	}
	return r
}

// String implements the [Stringer] interface.
func (r Radians) String() string {
	return strconv.FormatFloat(float64(r), 'f', -1, 64) + " rad"
}

// Degrees converts r into decimal degrees.
func (r Radians) Degrees() Degrees {
	return Degrees(r * 180.0 / math.Pi)
}

// Turns converts r into a number of turns.
func (r Radians) Turns() Turns {
	return Turns(r / 2 / math.Pi)
}

// Turns represents a number of complete revolutions around a sphere.
type Turns float64

// String implements the [Stringer] interface.
func (o Turns) String() string {
	return strconv.FormatFloat(float64(o), 'f', -1, 64)
}

// Degrees converts t into decimal degrees.
func (o Turns) Degrees() Degrees {
	return Degrees(o * 360.0)
}

// Radians converts t into radians.
func (o Turns) Radians() Radians {
	return Radians(o * 2 * math.Pi)
}

// Distance represents a great-circle distance in meters.
type Distance float64

// ParseDistance parses s as distance in meters.
func ParseDistance(s string) (Distance, error) {
	s = strings.TrimSuffix(s, "m")
	s = strings.TrimRightFunc(s, unicode.IsSpace)
	f, err := strconv.ParseFloat(s, 64)
	return Distance(f), err
}

// MustParseDistance parses s as distance in meters, but panics on error.
func MustParseDistance(s string) Distance {
	d, err := ParseDistance(s)
	if err != nil {
		panic(err)
	}
	return d
}

// String implements the [Stringer] interface.
func (d Distance) String() string {
	return strconv.FormatFloat(float64(d), 'f', -1, 64) + "m"
}

// DistanceOnEarth converts t turns into the great-circle distance, in meters.
func DistanceOnEarth(t Turns) Distance {
	return Distance(t) * EarthMeanCircumference
}

// Earth Fact Sheet
// https://nssdc.gsfc.nasa.gov/planetary/factsheet/earthfact.html
const (
	// EarthMeanRadius is the volumetric mean radius of the Earth.
	EarthMeanRadius = 6_371_000 * Meter
	// EarthMeanCircumference is the volumetric mean circumference of the Earth.
	EarthMeanCircumference = 2 * math.Pi * EarthMeanRadius

	// earthEquatorialRadius is the equatorial radius of the Earth.
	earthEquatorialRadius = 6_378_137 * Meter
	// earthEquatorialCircumference is the equatorial circumference of the Earth.
	earthEquatorialCircumference = 2 * math.Pi * earthEquatorialRadius

	// earthPolarRadius is the polar radius of the Earth.
	earthPolarRadius = 6_356_752 * Meter
	// earthPolarCircumference is the polar circumference of the Earth.
	earthPolarCircumference = 2 * math.Pi * earthPolarRadius
)
