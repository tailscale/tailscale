package neighbour

import (
	"math"
	"reflect"
	"testing"
)

func TestHaversine(t *testing.T) {
	one := Location{51.510357, -0.116773}  // King's College, London
	two := Location{38.889931, -77.009003} // The White House

	dist := one.Distance(two)
	want := 5897.658

	if math.Abs(want-dist) > 0.001 {
		t.Fatalf("distance mismatch; got %v, want %v", dist, want)
	}
}

func TestNeighbours(t *testing.T) {
	// Provincial capitals
	capitals := []Location{
		{48.4283182, -123.3649533}, // Victoria, BC, Canada
		{60.721571, -135.054932},   // Whitehorse, YT, Canada
		{53.5462055, -113.491241},  // Edmonton, AB, Canada
		{62.4540807, -114.377385},  // Yellowknife, NT, Canada
		{50.44876, -104.61731},     // Regina, SK, Canada
		{49.8955367, -97.1384584},  // Winnipeg, MB, Canada
		{63.74944, -68.521857},     // Iqaluit, NU, Canada
		{43.6534817, -79.3839347},  // Toronto, ON, Canada
		{45.5031824, -73.5698065},  // Montreal, QC, Canada
		{45.94780155, -66.6534707}, // Fredericton, NB, Canada
		{44.648618, -63.5859487},   // Halifax, NS, Canada
		{46.234953, -63.132935},    // Charlottetown, PE, Canada
		{47.5614705, -52.7126162},  // St. John’s, NL, Canada
	}

	// Thunder Bay, Ontario, Canada
	point := Location{48.382221, -89.246109}
	nearest := Neighbours(point, 4, capitals)
	want := []Location{
		{49.8955367, -97.1384584}, // Winnipeg, MB, Canada
		{43.6534817, -79.3839347}, // Toronto, ON, Canada
		{50.44876, -104.61731},    // Regina, SK, Canada
		{45.5031824, -73.5698065}, // Montreal, QC, Canada
	}
	if !reflect.DeepEqual(nearest, want) {
		t.Errorf("nearest points mismatch\ngot: %v\nwant: %v", nearest, want)
	}
}
