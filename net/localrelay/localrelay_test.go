package localrelay

import (
	"testing"

	"tailscale.com/types/key"
)

func TestAdvertisementRoundTrip(t *testing.T) {
	var disco key.DiscoPublic
	got, err := ParseAdvertisement(MarshalAdvertisement(disco, 41641))
	if err != nil {
		t.Fatalf("ParseAdvertisement: %v", err)
	}
	if got.Disco != disco {
		t.Fatalf("disco mismatch: got %v want %v", got.Disco, disco)
	}
	if got.Port != 41641 {
		t.Fatalf("port = %d, want 41641", got.Port)
	}
}
