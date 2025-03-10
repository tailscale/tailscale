package currenttime

import (
	"testing"
	"time"
)

func TestMinTime(t *testing.T) {
	// The baked-in time should always be before the current time.
	now := time.Now()
	if !minCurrentTime.Before(now) {
		t.Fatalf("minCurrentTime is not before the current time: %v >= %v", minCurrentTime, now)
	}
}
