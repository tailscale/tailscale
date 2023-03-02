// Package neighbour contains a basic non-optimized nearest-neighbour
// algorithm implementation for terrestrial GPS coordinates.
package neighbour

import (
	"math"

	"golang.org/x/exp/slices"
)

// Location is a latitude/longitude pair representing a point on Earth.
type Location struct {
	Latitude  float64
	Longitude float64
}

// Distance calculates the great-circle distance between two points using the
// Haversine formula, in kilometers.
//
// This is also known as the "as-the-crow-flies" distance.
func (l Location) Distance(other Location) float64 {
	// For the following variable definitions:
	//    φ is latitude ("phi")
	//    λ is longitude ("lambda")
	//    R is earth’s radius (mean radius = 6,371km)
	//
	// We can calculate the distance using the haversine formula as such:
	//    a = sin²((φB - φA)/2) + cos φA * cos φB * sin²((λB - λA)/2)
	//    c = 2 * atan2( √a, √(1−a) )
	//    d = R * c

	// Convert our latitude/longitude to radians, since the various math
	// functions take radians but latitude/longitude are in degrees.
	lat1, lon1 := degreesToRadians(l.Latitude), degreesToRadians(l.Longitude)
	lat2, lon2 := degreesToRadians(other.Latitude), degreesToRadians(other.Longitude)

	deltaPhi := lat2 - lat1
	deltaLambda := lon2 - lon1

	// Haversine
	a := math.Pow(math.Sin(deltaPhi/2), 2) +
		math.Cos(lat1)*math.Cos(lat2)*math.Pow(math.Sin(deltaLambda/2), 2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	// Return the distance in km.
	const earthRadiusKm = 6371
	return c * earthRadiusKm
}

func degreesToRadians(d float64) float64 {
	return d * math.Pi / 180
}

// Neighbours returns the nearest n neighbours to the provided point from the
// set of candidates.
func Neighbours(point Location, n int, candidates []Location) []Location {
	// Calculate all distances up-front to avoid recalculating during the
	// sort below.
	distances := map[Location]float64{}
	for _, candidate := range candidates {
		distances[candidate] = candidate.Distance(point)
	}

	// Sort the candidates slice by their distance to the provided point.
	candidates = slices.Clone(candidates)
	slices.SortFunc(candidates, func(a, b Location) bool {
		return distances[a] < distances[b]
	})

	return candidates[:n]
}
