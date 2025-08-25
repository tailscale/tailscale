package controlclient

import (
	"os"
	"testing"
)

func TestChooseControlProxyURL_OnionDefaultsToTor(t *testing.T) {
	os.Unsetenv("TS_CONTROL_PROXY")
	got := chooseControlProxyURL("http://abc123def456.onion:8080", "")
	want := "socks5h://127.0.0.1:9050"
	if got != want {
		t.Fatalf("chooseControlProxyURL(.onion) = %q; want %q", got, want)
	}
}

func TestChooseControlProxyURL_EnvOverrideWins(t *testing.T) {
	override := "socks5h://127.0.0.1:9150"
	got := chooseControlProxyURL("http://example.com", override)
	if got != override {
		t.Fatalf("chooseControlProxyURL(env override) = %q; want %q", got, override)
	}
}

func TestChooseControlProxyURL_NoProxyForNonOnion(t *testing.T) {
	os.Unsetenv("TS_CONTROL_PROXY")
	got := chooseControlProxyURL("https://headscale.example.internal:443", "")
	if got != "" {
		t.Fatalf("chooseControlProxyURL(non-onion) = %q; want empty", got)
	}
}