// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package geo_test

import (
	"fmt"
	"math"
	"testing"
	"testing/quick"

	"tailscale.com/types/geo"
)

func TestPointZero(t *testing.T) {
	var zero geo.Point

	if got := zero.IsZero(); !got {
		t.Errorf("IsZero() got %t", got)
	}

	if got := zero.Valid(); got {
		t.Errorf("Valid() got %t", got)
	}

	wantErr := geo.ErrBadPoint.Error()
	if _, _, err := zero.LatLng(); err.Error() != wantErr {
		t.Errorf("LatLng() err %q, want %q", err, wantErr)
	}

	wantStr := "nowhere"
	if got := zero.String(); got != wantStr {
		t.Errorf("String() got %q, want %q", got, wantStr)
	}

	wantB := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	if b, err := zero.MarshalBinary(); err != nil {
		t.Errorf("MarshalBinary() err %q, want nil", err)
	} else if string(b) != string(wantB) {
		t.Errorf("MarshalBinary got %q, want %q", b, wantB)
	}

	wantI := uint64(0x00000000)
	if i, err := zero.MarshalUint64(); err != nil {
		t.Errorf("MarshalUint64() err %q, want nil", err)
	} else if i != wantI {
		t.Errorf("MarshalUint64 got %v, want %v", i, wantI)
	}
}

func TestPoint(t *testing.T) {
	for _, tt := range []struct {
		name       string
		lat        geo.Degrees
		lng        geo.Degrees
		wantLat    geo.Degrees
		wantLng    geo.Degrees
		wantString string
		wantText   string
	}{
		{
			name:       "null-island",
			lat:        +0.0,
			lng:        +0.0,
			wantLat:    +0.0,
			wantLng:    +0.0,
			wantString: "+0° +0°",
			wantText:   "POINT (0 0)",
		},
		{
			name:       "north-pole",
			lat:        +90.0,
			lng:        +0.0,
			wantLat:    +90.0,
			wantLng:    +0.0,
			wantString: "+90° +0°",
			wantText:   "POINT (0 90)",
		},
		{
			name:       "south-pole",
			lat:        -90.0,
			lng:        +0.0,
			wantLat:    -90.0,
			wantLng:    +0.0,
			wantString: "-90° +0°",
			wantText:   "POINT (0 -90)",
		},
		{
			name:       "north-pole-weird-longitude",
			lat:        +90.0,
			lng:        +1.0,
			wantLat:    +90.0,
			wantLng:    +0.0,
			wantString: "+90° +0°",
			wantText:   "POINT (0 90)",
		},
		{
			name:       "south-pole-weird-longitude",
			lat:        -90.0,
			lng:        +1.0,
			wantLat:    -90.0,
			wantLng:    +0.0,
			wantString: "-90° +0°",
			wantText:   "POINT (0 -90)",
		},
		{
			name:       "almost-north",
			lat:        +89.0,
			lng:        +0.0,
			wantLat:    +89.0,
			wantLng:    +0.0,
			wantString: "+89° +0°",
			wantText:   "POINT (0 89)",
		},
		{
			name:       "past-north",
			lat:        +91.0,
			lng:        +0.0,
			wantLat:    +89.0,
			wantLng:    +180.0,
			wantString: "+89° +180°",
			wantText:   "POINT (180 89)",
		},
		{
			name:       "almost-south",
			lat:        -89.0,
			lng:        +0.0,
			wantLat:    -89.0,
			wantLng:    +0.0,
			wantString: "-89° +0°",
			wantText:   "POINT (0 -89)",
		},
		{
			name:       "past-south",
			lat:        -91.0,
			lng:        +0.0,
			wantLat:    -89.0,
			wantLng:    +180.0,
			wantString: "-89° +180°",
			wantText:   "POINT (180 -89)",
		},
		{
			name:       "antimeridian-north",
			lat:        +180.0,
			lng:        +0.0,
			wantLat:    +0.0,
			wantLng:    +180.0,
			wantString: "+0° +180°",
			wantText:   "POINT (180 0)",
		},
		{
			name:       "antimeridian-south",
			lat:        -180.0,
			lng:        +0.0,
			wantLat:    +0.0,
			wantLng:    +180.0,
			wantString: "+0° +180°",
			wantText:   "POINT (180 0)",
		},
		{
			name:       "almost-antimeridian-north",
			lat:        +179.0,
			lng:        +0.0,
			wantLat:    +1.0,
			wantLng:    +180.0,
			wantString: "+1° +180°",
			wantText:   "POINT (180 1)",
		},
		{
			name:       "past-antimeridian-north",
			lat:        +181.0,
			lng:        +0.0,
			wantLat:    -1.0,
			wantLng:    +180.0,
			wantString: "-1° +180°",
			wantText:   "POINT (180 -1)",
		},
		{
			name:       "almost-antimeridian-south",
			lat:        -179.0,
			lng:        +0.0,
			wantLat:    -1.0,
			wantLng:    +180.0,
			wantString: "-1° +180°",
			wantText:   "POINT (180 -1)",
		},
		{
			name:       "past-antimeridian-south",
			lat:        -181.0,
			lng:        +0.0,
			wantLat:    +1.0,
			wantLng:    +180.0,
			wantString: "+1° +180°",
			wantText:   "POINT (180 1)",
		},
		{
			name:       "circumnavigate-north",
			lat:        +360.0,
			lng:        +1.0,
			wantLat:    +0.0,
			wantLng:    +1.0,
			wantString: "+0° +1°",
			wantText:   "POINT (1 0)",
		},
		{
			name:       "circumnavigate-south",
			lat:        -360.0,
			lng:        +1.0,
			wantLat:    +0.0,
			wantLng:    +1.0,
			wantString: "+0° +1°",
			wantText:   "POINT (1 0)",
		},
		{
			name:       "almost-circumnavigate-north",
			lat:        +359.0,
			lng:        +1.0,
			wantLat:    -1.0,
			wantLng:    +1.0,
			wantString: "-1° +1°",
			wantText:   "POINT (1 -1)",
		},
		{
			name:       "past-circumnavigate-north",
			lat:        +361.0,
			lng:        +1.0,
			wantLat:    +1.0,
			wantLng:    +1.0,
			wantString: "+1° +1°",
			wantText:   "POINT (1 1)",
		},
		{
			name:       "almost-circumnavigate-south",
			lat:        -359.0,
			lng:        +1.0,
			wantLat:    +1.0,
			wantLng:    +1.0,
			wantString: "+1° +1°",
			wantText:   "POINT (1 1)",
		},
		{
			name:       "past-circumnavigate-south",
			lat:        -361.0,
			lng:        +1.0,
			wantLat:    -1.0,
			wantLng:    +1.0,
			wantString: "-1° +1°",
			wantText:   "POINT (1 -1)",
		},
		{
			name:       "antimeridian-east",
			lat:        +0.0,
			lng:        +180.0,
			wantLat:    +0.0,
			wantLng:    +180.0,
			wantString: "+0° +180°",
			wantText:   "POINT (180 0)",
		},
		{
			name:       "antimeridian-west",
			lat:        +0.0,
			lng:        -180.0,
			wantLat:    +0.0,
			wantLng:    +180.0,
			wantString: "+0° +180°",
			wantText:   "POINT (180 0)",
		},
		{
			name:       "almost-antimeridian-east",
			lat:        +0.0,
			lng:        +179.0,
			wantLat:    +0.0,
			wantLng:    +179.0,
			wantString: "+0° +179°",
			wantText:   "POINT (179 0)",
		},
		{
			name:       "past-antimeridian-east",
			lat:        +0.0,
			lng:        +181.0,
			wantLat:    +0.0,
			wantLng:    -179.0,
			wantString: "+0° -179°",
			wantText:   "POINT (-179 0)",
		},
		{
			name:       "almost-antimeridian-west",
			lat:        +0.0,
			lng:        -179.0,
			wantLat:    +0.0,
			wantLng:    -179.0,
			wantString: "+0° -179°",
			wantText:   "POINT (-179 0)",
		},
		{
			name:       "past-antimeridian-west",
			lat:        +0.0,
			lng:        -181.0,
			wantLat:    +0.0,
			wantLng:    +179.0,
			wantString: "+0° +179°",
			wantText:   "POINT (179 0)",
		},
		{
			name:       "montreal",
			lat:        +45.508888,
			lng:        -73.561668,
			wantLat:    +45.508888,
			wantLng:    -73.561668,
			wantString: "+45.508888° -73.561668°",
			wantText:   "POINT (-73.561668 45.508888)",
		},
		{
			name:       "canada",
			lat:        57.550480044655636,
			lng:        -98.41680517868062,
			wantLat:    57.550480044655636,
			wantLng:    -98.41680517868062,
			wantString: "+57.550480044655636° -98.41680517868062°",
			wantText:   "POINT (-98.41680517868062 57.550480044655636)",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := geo.MakePoint(tt.lat, tt.lng)

			lat, lng, err := p.LatLng()
			if !approx(lat, tt.wantLat) {
				t.Errorf("MakePoint: lat %v, want %v", lat, tt.wantLat)
			}
			if !approx(lng, tt.wantLng) {
				t.Errorf("MakePoint: lng %v, want %v", lng, tt.wantLng)
			}
			if err != nil {
				t.Fatalf("LatLng: err %q, expected nil", err)
			}

			if got := p.String(); got != tt.wantString {
				t.Errorf("String: got %q, wantString %q", got, tt.wantString)
			}

			txt, err := p.MarshalText()
			if err != nil {
				t.Errorf("Text: err %q, expected nil", err)
			} else if string(txt) != tt.wantText {
				t.Errorf("Text: got %q, wantText %q", txt, tt.wantText)
			}

			b, err := p.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: err %q, expected nil", err)
			}

			var q geo.Point
			if err := q.UnmarshalBinary(b); err != nil {
				t.Fatalf("UnmarshalBinary: err %q, expected nil", err)
			}
			if !q.EqualApprox(p, -1) {
				t.Errorf("UnmarshalBinary: roundtrip failed: %#v != %#v", q, p)
			}

			i, err := p.MarshalUint64()
			if err != nil {
				t.Fatalf("MarshalUint64: err %q, expected nil", err)
			}

			var r geo.Point
			if err := r.UnmarshalUint64(i); err != nil {
				t.Fatalf("UnmarshalUint64: err %r, expected nil", err)
			}
			if !q.EqualApprox(r, -1) {
				t.Errorf("UnmarshalUint64: roundtrip failed: %#v != %#v", r, p)
			}
		})
	}
}

func TestPointMarshalBinary(t *testing.T) {
	roundtrip := func(p geo.Point) error {
		b, err := p.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal: %v", err)
		}
		var q geo.Point
		if err := q.UnmarshalBinary(b); err != nil {
			return fmt.Errorf("unmarshal: %v", err)
		}
		if q != p {
			return fmt.Errorf("%#v != %#v", q, p)
		}
		return nil
	}

	t.Run("nowhere", func(t *testing.T) {
		var nowhere geo.Point
		if err := roundtrip(nowhere); err != nil {
			t.Errorf("roundtrip: %v", err)
		}
	})

	t.Run("quick-check", func(t *testing.T) {
		f := func(lat geo.Degrees, lng geo.Degrees) (ok bool) {
			pt := geo.MakePoint(lat, lng)
			if err := roundtrip(pt); err != nil {
				t.Errorf("roundtrip: %v", err)
			}
			return !t.Failed()
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
}

func TestPointMarshalUint64(t *testing.T) {
	t.Skip("skip")
	roundtrip := func(p geo.Point) error {
		i, err := p.MarshalUint64()
		if err != nil {
			return fmt.Errorf("marshal: %v", err)
		}
		var q geo.Point
		if err := q.UnmarshalUint64(i); err != nil {
			return fmt.Errorf("unmarshal: %v", err)
		}
		if q != p {
			return fmt.Errorf("%#v != %#v", q, p)
		}
		return nil
	}

	t.Run("nowhere", func(t *testing.T) {
		var nowhere geo.Point
		if err := roundtrip(nowhere); err != nil {
			t.Errorf("roundtrip: %v", err)
		}
	})

	t.Run("quick-check", func(t *testing.T) {
		f := func(lat geo.Degrees, lng geo.Degrees) (ok bool) {
			if err := roundtrip(geo.MakePoint(lat, lng)); err != nil {
				t.Errorf("roundtrip: %v", err)
			}
			return !t.Failed()
		}
		if err := quick.Check(f, nil); err != nil {
			t.Error(err)
		}
	})
}

func TestPointSphericalAngleTo(t *testing.T) {
	const earthRadius = 6371.000 // volumetric mean radius (km)
	const kmToRad = 1 / earthRadius
	for _, tt := range []struct {
		name    string
		x       geo.Point
		y       geo.Point
		want    geo.Radians
		wantErr string
	}{
		{
			name: "same-point-null-island",
			x:    geo.MakePoint(0, 0),
			y:    geo.MakePoint(0, 0),
			want: 0.0 * geo.Radian,
		},
		{
			name: "same-point-north-pole",
			x:    geo.MakePoint(+90, 0),
			y:    geo.MakePoint(+90, +90),
			want: 0.0 * geo.Radian,
		},
		{
			name: "same-point-south-pole",
			x:    geo.MakePoint(-90, 0),
			y:    geo.MakePoint(-90, -90),
			want: 0.0 * geo.Radian,
		},
		{
			name: "north-pole-to-south-pole",
			x:    geo.MakePoint(+90, 0),
			y:    geo.MakePoint(-90, -90),
			want: math.Pi * geo.Radian,
		},
		{
			name: "toronto-to-montreal",
			x:    geo.MakePoint(+43.6532, -79.3832),
			y:    geo.MakePoint(+45.5019, -73.5674),
			want: 504.26 * kmToRad * geo.Radian,
		},
		{
			name: "sydney-to-san-francisco",
			x:    geo.MakePoint(-33.8727, +151.2057),
			y:    geo.MakePoint(+37.7749, -122.4194),
			want: 11948.18 * kmToRad * geo.Radian,
		},
		{
			name: "new-york-to-paris",
			x:    geo.MakePoint(+40.7128, -74.0060),
			y:    geo.MakePoint(+48.8575, +2.3514),
			want: 5837.15 * kmToRad * geo.Radian,
		},
		{
			name: "seattle-to-tokyo",
			x:    geo.MakePoint(+47.6061, -122.3328),
			y:    geo.MakePoint(+35.6764, +139.6500),
			want: 7700.00 * kmToRad * geo.Radian,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.x.SphericalAngleTo(tt.y)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("err %q, expected nil", err)
			}
			if tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr) {
				t.Fatalf("err %q, expected %q", err, tt.wantErr)
			}
			if tt.wantErr != "" {
				return
			}

			if !approx(got, tt.want) {
				t.Errorf("x to y: got %v, want %v", got, tt.want)
			}

			// Distance should be commutative
			got, err = tt.y.SphericalAngleTo(tt.x)
			if err != nil {
				t.Fatalf("err %q, expected nil", err)
			}
			if !approx(got, tt.want) {
				t.Errorf("y to x: got %v, want %v", got, tt.want)
			}
			t.Logf("x to y: %v km", got/kmToRad)
		})
	}
}

func approx[T ~float64](x, y T) bool {
	return math.Abs(float64(x)-float64(y)) <= 1e-5
}
