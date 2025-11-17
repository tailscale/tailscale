// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package geo_test

import (
	"testing"
	"testing/quick"

	"tailscale.com/types/geo"
)

func TestPointAnonymize(t *testing.T) {
	t.Run("nowhere", func(t *testing.T) {
		var zero geo.Point
		p := zero.Quantize()
		want := zero.Valid()
		if got := p.Valid(); got != want {
			t.Fatalf("zero.Valid %t, want %t", got, want)
		}
	})

	t.Run("separation", func(t *testing.T) {
		// Walk from the south pole to the north pole and check that each
		// point on the latitude is approximately MinSeparation apart.
		const southPole = -90 * geo.Degree
		const northPole = 90 * geo.Degree
		const dateLine = 180 * geo.Degree

		llat := southPole
		for lat := llat; lat <= northPole; lat += 0x1p-4 {
			last := geo.MakePoint(llat, 0)
			cur := geo.MakePoint(lat, 0)
			anon := cur.Quantize()
			switch latlng, g, err := anon.LatLng(); {
			case err != nil:
				t.Fatal(err)
			case lat == southPole:
				// initialize llng, to the first snapped longitude
				llat = latlng
				goto Lng
			case g != 0:
				t.Fatalf("%v is west or east of %v", anon, last)
			case latlng < llat:
				t.Fatalf("%v is south of %v", anon, last)
			case latlng == llat:
				continue
			case latlng > llat:
				switch dist, err := last.DistanceTo(anon); {
				case err != nil:
					t.Fatal(err)
				case dist == 0.0:
					continue
				case dist < geo.MinSeparation:
					t.Logf("lat=%v last=%v cur=%v anon=%v", lat, last, cur, anon)
					t.Fatalf("%v is too close to %v", anon, last)
				default:
					llat = latlng
				}
			}

		Lng:
			llng := dateLine
			for lng := llng; lng <= dateLine && lng >= -dateLine; lng -= 0x1p-3 {
				last := geo.MakePoint(llat, llng)
				cur := geo.MakePoint(lat, lng)
				anon := cur.Quantize()
				switch latlng, g, err := anon.LatLng(); {
				case err != nil:
					t.Fatal(err)
				case lng == dateLine:
					// initialize llng, to the first snapped longitude
					llng = g
					continue
				case latlng != llat:
					t.Fatalf("%v is north or south of %v", anon, last)
				case g != llng:
					const tolerance = geo.MinSeparation * 0x1p-9
					switch dist, err := last.DistanceTo(anon); {
					case err != nil:
						t.Fatal(err)
					case dist < tolerance:
						continue
					case dist < (geo.MinSeparation - tolerance):
						t.Logf("lat=%v lng=%v last=%v cur=%v anon=%v", lat, lng, last, cur, anon)
						t.Fatalf("%v is too close to %v: %v", anon, last, dist)
					default:
						llng = g
					}

				}
			}
		}
		if llat == southPole {
			t.Fatal("llat never incremented")
		}
	})

	t.Run("quick-check", func(t *testing.T) {
		f := func(lat, lng geo.Degrees) bool {
			p := geo.MakePoint(lat, lng)
			q := p.Quantize()
			t.Logf("quantize %v = %v", p, q)

			lat, lng, err := q.LatLng()
			if err != nil {
				t.Errorf("err %v, want nil", err)
				return !t.Failed()
			}

			if lat < -90*geo.Degree || lat > 90*geo.Degree {
				t.Errorf("lat outside [-90°, +90°]: %v", lat)
			}
			if lng < -180*geo.Degree || lng > 180*geo.Degree {
				t.Errorf("lng outside [-180°, +180°], %v", lng)
			}

			if dist, err := p.DistanceTo(q); err != nil {
				t.Error(err)
			} else if dist > (geo.MinSeparation * 2) {
				t.Errorf("moved too far: %v", dist)
			}

			return !t.Failed()
		}
		if err := quick.Check(f, nil); err != nil {
			t.Fatal(err)
		}
	})
}
