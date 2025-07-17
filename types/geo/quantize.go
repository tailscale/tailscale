// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package geo

import (
	"math"
	"sync"
)

// MinSeparation is the minimum separation between two points after quantizing.
// [Point.Quantize] guarantees that two points will either be snapped to exactly
// the same point, which conflates multiple positions together, or that the two
// points will be far enough apart that successfully performing most reverse
// lookups would be highly improbable.
const MinSeparation = 50_000 * Meter

// Latitude
var (
	// numSepsEquatorToPole is the number of separations between a point on
	// the equator to a point on a pole, that satisfies [minPointSep]. In
	// other words, the number of separations between 0° and +90° degrees
	// latitude.
	numSepsEquatorToPole = int(math.Floor(float64(
		earthPolarCircumference / MinSeparation / 4)))

	// latSep is the number of degrees between two adjacent latitudinal
	// points. In other words, the next point going straight north of
	// 0° would be latSep°.
	latSep = Degrees(90.0 / float64(numSepsEquatorToPole))
)

// snapToLat returns the number of the nearest latitudinal separation to
// lat. A positive result is north of the equator, a negative result is south,
// and zero is the equator itself. For example, a result of -1 would mean a
// point that is [latSep] south of the equator.
func snapToLat(lat Degrees) int {
	return int(math.Round(float64(lat / latSep)))
}

// lngSep is a lookup table for the number of degrees between two adjacent
// longitudinal separations. where the index corresponds to the absolute value
// of the latitude separation. The first value corresponds to the equator and
// the last value corresponds to the separation before the pole. There is no
// value for the pole itself, because longitude has no meaning there.
//
// [lngSep] is calculated on init, which is so quick and will be used so often
// that the startup cost is negligible.
var lngSep = sync.OnceValue(func() []Degrees {
	lut := make([]Degrees, numSepsEquatorToPole)

	// i ranges from the equator to a pole
	for i := range len(lut) {
		// lat ranges from [0°, 90°], because the southern hemisphere is
		// a reflection of the northern one.
		lat := Degrees(i) * latSep
		ratio := math.Cos(float64(lat.Radians()))
		circ := Distance(ratio) * earthEquatorialCircumference
		num := int(math.Floor(float64(circ / MinSeparation)))
		// We define lut[0] as 0°, lut[len(lut)] to be the north pole,
		// which means -lut[len(lut)] is the south pole.
		lut[i] = Degrees(360.0 / float64(num))
	}
	return lut
})

// snapToLatLng returns the number of the nearest latitudinal separation to lat,
// and the nearest longitudinal separation to lng.
func snapToLatLng(lat, lng Degrees) (Degrees, Degrees) {
	latN := snapToLat(lat)

	// absolute index into lngSep
	n := latN
	if n < 0 {
		n = -latN
	}

	lngSep := lngSep()
	if n < len(lngSep) {
		sep := lngSep[n]
		lngN := int(math.Round(float64(lng / sep)))
		return Degrees(latN) * latSep, Degrees(lngN) * sep
	}
	if latN < 0 { // south pole
		return -90 * Degree, 0 * Degree
	} else { // north pole
		return +90 * Degree, 0 * Degree
	}
}

// Quantize returns a new [Point] after throwing away enough location data in p
// so that it would be difficult to distinguish a node among all the other nodes
// in its general vicinity. One caveat is that if there’s only one point in an
// obscure location, someone could triangulate the node using additional data.
//
// This method is stable: given the same p, it will always return the same
// result. It is equivalent to snapping to points on Earth that are at least
// [MinSeparation] apart.
func (p Point) Quantize() Point {
	if p.IsZero() {
		return p
	}

	lat, lng := snapToLatLng(p.lat, p.lng180-180)
	return MakePoint(lat, lng)
}
