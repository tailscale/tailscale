// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dnsname

import (
	"strings"
	"testing"
)

func TestFQDN(t *testing.T) {
	tests := []struct {
		in         string
		want       FQDN
		wantErr    bool
		wantLabels int
	}{
		{"", ".", false, 0},
		{".", ".", false, 0},
		{"foo.com", "foo.com.", false, 2},
		{"foo.com.", "foo.com.", false, 2},
		{".foo.com.", "foo.com.", false, 2},
		{".foo.com", "foo.com.", false, 2},
		{"com", "com.", false, 1},
		{"www.tailscale.com", "www.tailscale.com.", false, 3},
		{"_ssh._tcp.tailscale.com", "_ssh._tcp.tailscale.com.", false, 4},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", "", true, 0},
		{strings.Repeat("aaaaa.", 60) + "com", "", true, 0},
		{"foo..com", "", true, 0},
	}

	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			got, err := ToFQDN(test.in)
			if got != test.want {
				t.Errorf("ToFQDN(%q) got %q, want %q", test.in, got, test.want)
			}
			if (err != nil) != test.wantErr {
				t.Errorf("ToFQDN(%q) err %v, wantErr=%v", test.in, err, test.wantErr)
			}
			if err != nil {
				return
			}

			gotDot := got.WithTrailingDot()
			if gotDot != string(test.want) {
				t.Errorf("ToFQDN(%q).WithTrailingDot() got %q, want %q", test.in, gotDot, test.want)
			}
			gotNoDot := got.WithoutTrailingDot()
			wantNoDot := string(test.want)[:len(test.want)-1]
			if gotNoDot != wantNoDot {
				t.Errorf("ToFQDN(%q).WithoutTrailingDot() got %q, want %q", test.in, gotNoDot, wantNoDot)
			}

			if gotLabels := got.NumLabels(); gotLabels != test.wantLabels {
				t.Errorf("ToFQDN(%q).NumLabels() got %v, want %v", test.in, gotLabels, test.wantLabels)
			}
		})
	}
}

func TestFQDNTooLong(t *testing.T) {
	// RFC 1035 says a dns name has a max size of 255 octets, and is represented as labels of len+ASCII chars so
	//   example.com
	// is represented as
	//   7example3com0
	// which is to say that if we have a trailing dot then the dots cancel out all the len bytes except the first and
	// we can accept 254 chars.

	// This name is max length
	name := "aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.example.com."
	if len(name) != 254 {
		t.Fatalf("name should be 254 chars including trailing . (len is %d)", len(name))
	}
	got, err := ToFQDN(name)
	if err != nil {
		t.Fatalf("want: no error, got: %v", err)
	}
	if string(got) != name {
		t.Fatalf("want: %s, got: %s", name, got)
	}

	// This name is too long
	name = "x" + name
	got, err = ToFQDN(name)
	if got != "" {
		t.Fatalf("want: \"\", got: %s", got)
	}
	if err == nil || !strings.HasSuffix(err.Error(), "is too long to be a DNS name") {
		t.Fatalf("want: error to end with \"is too long to be a DNS name\", got: %v", err)
	}
}

func TestFQDNContains(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"", "", true},
		{"", "foo.com", true},
		{"foo.com", "", false},
		{"tailscale.com", "www.tailscale.com", true},
		{"www.tailscale.com", "tailscale.com", false},
		{"scale.com", "tailscale.com", false},
		{"foo.com", "foo.com", true},
	}

	for _, test := range tests {
		t.Run(test.a+"_"+test.b, func(t *testing.T) {
			a, err := ToFQDN(test.a)
			if err != nil {
				t.Fatalf("ToFQDN(%q): %v", test.a, err)
			}
			b, err := ToFQDN(test.b)
			if err != nil {
				t.Fatalf("ToFQDN(%q): %v", test.b, err)
			}

			if got := a.Contains(b); got != test.want {
				t.Errorf("ToFQDN(%q).Contains(%q) got %v, want %v", a, b, got, test.want)
			}
		})
	}
}

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"space", " ", ""},
		{"upper", "OBERON", "oberon"},
		{"mixed", "Avery's iPhone 4(SE)", "averys-iphone-4se"},
		{"dotted", "mon.ipn.dev", "mon-ipn-dev"},
		{"email", "admin@example.com", "admin-example-com"},
		{"boundary", ".bound.ary.", "bound-ary"},
		{"bad_trailing", "a-", "a"},
		{"bad_leading", "-a", "a"},
		{"bad_both", "-a-", "a"},
		{
			"overlong",
			strings.Repeat("test.", 20),
			"test-test-test-test-test-test-test-test-test-test-test-test-tes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeLabel(tt.in)
			if got != tt.want {
				t.Errorf("want %q; got %q", tt.want, got)
			}
		})
	}
}

func TestTrimCommonSuffixes(t *testing.T) {
	tests := []struct {
		hostname string
		want     string
	}{
		{"computer.local", "computer"},
		{"computer.localdomain", "computer"},
		{"computer.lan", "computer"},
		{"computer.mynetwork", "computer.mynetwork"},
	}
	for _, tt := range tests {
		got := TrimCommonSuffixes(tt.hostname)
		if got != tt.want {
			t.Errorf("TrimCommonSuffixes(%q) = %q; want %q", tt.hostname, got, tt.want)
		}
	}
}

func TestHasSuffix(t *testing.T) {
	tests := []struct {
		name, suffix string
		want         bool
	}{
		{"foo.com", "com", true},
		{"foo.com.", "com", true},
		{"foo.com.", "com.", true},
		{"foo.com", ".com", true},

		{"", "", false},
		{"foo.com.", "", false},
		{"foo.com.", "o.com", false},
	}
	for _, tt := range tests {
		got := HasSuffix(tt.name, tt.suffix)
		if got != tt.want {
			t.Errorf("HasSuffix(%q, %q) = %v; want %v", tt.name, tt.suffix, got, tt.want)
		}
	}
}

func TestTrimSuffix(t *testing.T) {
	tests := []struct {
		name   string
		suffix string
		want   string
	}{
		{"foo.magicdnssuffix.", "magicdnssuffix", "foo"},
		{"foo.magicdnssuffix", "magicdnssuffix", "foo"},
		{"foo.magicdnssuffix", ".magicdnssuffix", "foo"},
		{"foo.anothersuffix", "magicdnssuffix", "foo.anothersuffix"},
		{"foo.anothersuffix.", "magicdnssuffix", "foo.anothersuffix"},
		{"a.b.c.d", "c.d", "a.b"},
		{"name.", "foo", "name"},
	}
	for _, tt := range tests {
		got := TrimSuffix(tt.name, tt.suffix)
		if got != tt.want {
			t.Errorf("TrimSuffix(%q, %q) = %q; want %q", tt.name, tt.suffix, got, tt.want)
		}
	}
}

func TestValidHostname(t *testing.T) {
	tests := []struct {
		hostname string
		wantErr  string
	}{
		{"example", ""},
		{"example.com", ""},
		{" example", `must start with a letter or number`},
		{"example-.com", `must end with a letter or number`},
		{strings.Repeat("a", 63), ""},
		{strings.Repeat("a", 64), `is too long, max length is 63 bytes`},
		{strings.Repeat(strings.Repeat("a", 63)+".", 4), "is too long to be a DNS name"},
		{"www.what🤦lol.example.com", "contains invalid character"},
	}

	for _, test := range tests {
		t.Run(test.hostname, func(t *testing.T) {
			err := ValidHostname(test.hostname)
			if (err == nil) != (test.wantErr == "") || (err != nil && !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("ValidHostname(%s)=%v; expected %v", test.hostname, err, test.wantErr)
			}
		})
	}
}

var sinkFQDN FQDN

func BenchmarkToFQDN(b *testing.B) {
	tests := []string{
		"www.tailscale.com.",
		"www.tailscale.com",
		".www.tailscale.com",
		"_ssh._tcp.www.tailscale.com.",
		"_ssh._tcp.www.tailscale.com",
	}

	for _, test := range tests {
		b.Run(test, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				sinkFQDN, _ = ToFQDN(test)
			}
		})
	}
}
