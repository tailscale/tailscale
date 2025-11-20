// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package geo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// ErrBadPoint indicates that the point is malformed.
var ErrBadPoint = errors.New("not a valid point")

// Point represents a pair of latitude and longitude coordinates.
type Point struct {
	lat Degrees
	// lng180 is the longitude offset by +180° so the zero value is invalid
	// and +0+0/ is Point{lat: +0.0, lng180: +180.0}.
	lng180 Degrees
}

// MakePoint returns a Point representing a given latitude and longitude on
// a WGS 84 ellipsoid. The Coordinate Reference System is EPSG:4326.
// Latitude is wrapped to [-90°, +90°] and longitude to (-180°, +180°].
func MakePoint(latitude, longitude Degrees) Point {
	lat, lng := float64(latitude), float64(longitude)

	switch {
	case math.IsNaN(lat) || math.IsInf(lat, 0):
		// don’t wrap
	case lat < -90 || lat > 90:
		// Latitude wraps by flipping the longitude
		lat = math.Mod(lat, 360.0)
		switch {
		case lat == 0.0:
			lat = 0.0 // -0.0 == 0.0, but -0° is not valid
		case lat < -270.0:
			lat = +360.0 + lat
		case lat < -90.0:
			lat = -180.0 - lat
			lng += 180.0
		case lat > +270.0:
			lat = -360.0 + lat
		case lat > +90.0:
			lat = +180.0 - lat
			lng += 180.0
		}
	}

	switch {
	case lat == -90.0 || lat == +90.0:
		// By convention, the north and south poles have longitude 0°.
		lng = 0
	case math.IsNaN(lng) || math.IsInf(lng, 0):
		// don’t wrap
	case lng <= -180.0 || lng > 180.0:
		// Longitude wraps around normally
		lng = math.Mod(lng, 360.0)
		switch {
		case lng == 0.0:
			lng = 0.0 // -0.0 == 0.0, but -0° is not valid
		case lng <= -180.0:
			lng = +360.0 + lng
		case lng > +180.0:
			lng = -360.0 + lng
		}
	}

	return Point{
		lat:    Degrees(lat),
		lng180: Degrees(lng + 180.0),
	}
}

// Valid reports if p is a valid point.
func (p Point) Valid() bool {
	return !p.IsZero()
}

// LatLng reports the latitude and longitude.
func (p Point) LatLng() (lat, lng Degrees, err error) {
	if p.IsZero() {
		return 0 * Degree, 0 * Degree, ErrBadPoint
	}
	return p.lat, p.lng180 - 180.0*Degree, nil
}

// LatLng reports the latitude and longitude in float64. If err is nil, then lat
// and lng will never both be 0.0 to disambiguate between an empty struct and
// Null Island (0° 0°).
func (p Point) LatLngFloat64() (lat, lng float64, err error) {
	dlat, dlng, err := p.LatLng()
	if err != nil {
		return 0.0, 0.0, err
	}
	if dlat == 0.0 && dlng == 0.0 {
		// dlng must survive conversion to float32.
		dlng = math.SmallestNonzeroFloat32
	}
	return float64(dlat), float64(dlng), err
}

// SphericalAngleTo returns the angular distance from p to q, calculated on a
// spherical Earth.
func (p Point) SphericalAngleTo(q Point) (Radians, error) {
	pLat, pLng, pErr := p.LatLng()
	qLat, qLng, qErr := q.LatLng()
	switch {
	case pErr != nil && qErr != nil:
		return 0.0, fmt.Errorf("spherical distance from %v to %v: %w", p, q, errors.Join(pErr, qErr))
	case pErr != nil:
		return 0.0, fmt.Errorf("spherical distance from %v: %w", p, pErr)
	case qErr != nil:
		return 0.0, fmt.Errorf("spherical distance to %v: %w", q, qErr)
	}
	// The spherical law of cosines is accurate enough for close points when
	// using float64.
	//
	// The haversine formula is an alternative, but it is poorly behaved
	// when points are on opposite sides of the sphere.
	rLat, rLng := float64(pLat.Radians()), float64(pLng.Radians())
	sLat, sLng := float64(qLat.Radians()), float64(qLng.Radians())
	cosA := math.Sin(rLat)*math.Sin(sLat) +
		math.Cos(rLat)*math.Cos(sLat)*math.Cos(rLng-sLng)
	return Radians(math.Acos(cosA)), nil
}

// DistanceTo reports the great-circle distance between p and q, in meters.
func (p Point) DistanceTo(q Point) (Distance, error) {
	r, err := p.SphericalAngleTo(q)
	if err != nil {
		return 0, err
	}
	return DistanceOnEarth(r.Turns()), nil
}

// String returns a space-separated pair of latitude and longitude, in decimal
// degrees. Positive latitudes are in the northern hemisphere, and positive
// longitudes are east of the prime meridian. If p was not initialized, this
// will return "nowhere".
func (p Point) String() string {
	lat, lng, err := p.LatLng()
	if err != nil {
		if err == ErrBadPoint {
			return "nowhere"
		}
		panic(err)
	}

	return lat.String() + " " + lng.String()
}

// AppendBinary implements [encoding.BinaryAppender]. The output consists of two
// float32s in big-endian byte order: latitude and longitude offset by 180°.
// If p is not a valid, the output will be an 8-byte zero value.
func (p Point) AppendBinary(b []byte) ([]byte, error) {
	end := binary.BigEndian
	b = end.AppendUint32(b, math.Float32bits(float32(p.lat)))
	b = end.AppendUint32(b, math.Float32bits(float32(p.lng180)))
	return b, nil
}

// MarshalBinary implements [encoding.BinaryMarshaller]. The output matches that
// of calling [Point.AppendBinary].
func (p Point) MarshalBinary() ([]byte, error) {
	var b [8]byte
	return p.AppendBinary(b[:0])
}

// UnmarshalBinary implements [encoding.BinaryUnmarshaler]. It expects input
// that was formatted by [Point.AppendBinary]: in big-endian byte order, a
// float32 representing latitude followed by a float32 representing longitude
// offset by 180°. If latitude and longitude fall outside valid ranges, then
// an error is returned.
func (p *Point) UnmarshalBinary(data []byte) error {
	if len(data) < 8 { // Two uint32s are 8 bytes long
		return fmt.Errorf("%w: not enough data: %q", ErrBadPoint, data)
	}

	end := binary.BigEndian
	lat := Degrees(math.Float32frombits(end.Uint32(data[0:])))
	if lat < -90*Degree || lat > 90*Degree {
		return fmt.Errorf("%w: latitude outside [-90°, +90°]: %s", ErrBadPoint, lat)
	}
	lng180 := Degrees(math.Float32frombits(end.Uint32(data[4:])))
	if lng180 != 0 && (lng180 < 0*Degree || lng180 > 360*Degree) {
		// lng180 == 0 is OK: the zero value represents invalid points.
		lng := lng180 - 180*Degree
		return fmt.Errorf("%w: longitude outside (-180°, +180°]: %s", ErrBadPoint, lng)
	}

	p.lat = lat
	p.lng180 = lng180
	return nil
}

// AppendText implements [encoding.TextAppender]. The output is a point
// formatted as OGC Well-Known Text, as "POINT (longitude latitude)" where
// longitude and latitude are in decimal degrees. If p is not valid, the output
// will be "POINT EMPTY".
func (p Point) AppendText(b []byte) ([]byte, error) {
	if p.IsZero() {
		b = append(b, []byte("POINT EMPTY")...)
		return b, nil
	}

	lat, lng, err := p.LatLng()
	if err != nil {
		return b, err
	}

	b = append(b, []byte("POINT (")...)
	b = strconv.AppendFloat(b, float64(lng), 'f', -1, 64)
	b = append(b, ' ')
	b = strconv.AppendFloat(b, float64(lat), 'f', -1, 64)
	b = append(b, ')')
	return b, nil
}

// MarshalText implements [encoding.TextMarshaller]. The output matches that
// of calling [Point.AppendText].
func (p Point) MarshalText() ([]byte, error) {
	var b [8]byte
	return p.AppendText(b[:0])
}

// MarshalUint64 produces the same output as MashalBinary, encoded in a uint64.
func (p Point) MarshalUint64() (uint64, error) {
	b, err := p.MarshalBinary()
	return binary.NativeEndian.Uint64(b), err
}

// UnmarshalUint64 expects input formatted by MarshalUint64.
func (p *Point) UnmarshalUint64(v uint64) error {
	b := binary.NativeEndian.AppendUint64(nil, v)
	return p.UnmarshalBinary(b)
}

// IsZero reports if p is the zero value.
func (p Point) IsZero() bool {
	return p == Point{}
}

// EqualApprox reports if p and q are approximately equal: that is the absolute
// difference of both latitude and longitude are less than tol. If tol is
// negative, then tol defaults to a reasonably small number (10⁻⁵). If tol is
// zero, then p and q must be exactly equal.
func (p Point) EqualApprox(q Point, tol float64) bool {
	if tol == 0 {
		return p == q
	}

	if p.IsZero() && q.IsZero() {
		return true
	} else if p.IsZero() || q.IsZero() {
		return false
	}

	plat, plng, err := p.LatLng()
	if err != nil {
		panic(err)
	}
	qlat, qlng, err := q.LatLng()
	if err != nil {
		panic(err)
	}

	if tol < 0 {
		tol = 1e-5
	}

	dlat := float64(plat) - float64(qlat)
	dlng := float64(plng) - float64(qlng)
	return ((dlat < 0 && -dlat < tol) || (dlat >= 0 && dlat < tol)) &&
		((dlng < 0 && -dlng < tol) || (dlng >= 0 && dlng < tol))
}
