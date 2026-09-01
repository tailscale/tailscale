// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package geo

import (
	"math"
	"testing"
)

func FuzzPointSphericalAngleTo(f *testing.F) {
	for _, tt := range []struct{ xLat, xLng, yLat, yLng float64 }{
		{0.0, 0.0, 0.0, 0.0},
		{90.0, 0.0, 90.0, 90.0},
		{-90.0, 0.0, -90.0, -90.0},
		{90.0, 0.0, -90.0, -90.0},
		{43.6532, -79.3832, 45.5019, -73.5674},
		{-33.8727, 151.2057, 37.7749, -122.4194},
		{40.7128, -74.006, 48.8575, 2.3514},
		{47.6061, -122.3328, 35.6764, 139.65},
		{-6.0, 0.0, -6.0, 0.0},
	} {
		f.Add(tt.xLat, tt.xLng, tt.yLat, tt.yLng)
	}

	f.Fuzz(func(t *testing.T, xLat float64, xLng float64, yLat float64, yLng float64) {
		x := MakePoint(Degrees(xLat), Degrees(xLng))
		y := MakePoint(Degrees(yLat), Degrees(yLng))
		got, _ := x.SphericalAngleTo(y)
		if math.IsNaN(float64(got)) {
			t.Errorf("got NaN result with xLat=%f xLng=%f yLat=%f yLng=%f", xLat, xLng, yLat, yLng)
		}
	})
}
