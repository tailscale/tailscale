package dnscache

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"10.1.2.3", true},
		{"172.16.1.100", true},
		{"192.168.1.1", true},
		{"1.2.3.4", false},
	}

	for _, test := range tests {
		if got := isPrivateIP(net.ParseIP(test.ip)); got != test.want {
			t.Errorf("isPrivateIP(%q)=%v, want %v", test.ip, got, test.want)
		}
	}
}
