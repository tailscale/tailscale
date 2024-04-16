// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipproto

import (
	"encoding"
	"encoding/json"
	"fmt"
	"testing"

	"tailscale.com/util/must"
)

// Ensure that the Proto type implements encoding.TextMarshaler and
// encoding.TextUnmarshaler.
var (
	_ encoding.TextMarshaler   = (*Proto)(nil)
	_ encoding.TextUnmarshaler = (*Proto)(nil)
)

func TestHistoricalStringNames(t *testing.T) {
	// A subset of supported protocols were described with their lowercase String() representations and must remain supported.
	var historical = map[string]Proto{
		"icmpv4": ICMPv4,
		"igmp":   IGMP,
		"tcp":    TCP,
		"udp":    UDP,
		"dccp":   DCCP,
		"gre":    GRE,
		"sctp":   SCTP,
	}

	for name, proto := range historical {
		var p Proto
		must.Do(p.UnmarshalText([]byte(name)))
		if got, want := p, proto; got != want {
			t.Errorf("Proto.UnmarshalText(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestAcceptedNamesContainsPreferredNames(t *testing.T) {
	for proto, name := range preferredNames {
		if _, ok := acceptedNames[name]; !ok {
			t.Errorf("preferredNames[%q] = %v, but acceptedNames does not contain it", name, proto)
		}
	}
}

func TestProtoTextEncodingRoundTrip(t *testing.T) {
	for i := range 256 {
		text := must.Get(Proto(i).MarshalText())
		var p Proto
		must.Do(p.UnmarshalText(text))

		if got, want := p, Proto(i); got != want {
			t.Errorf("Proto(%d) round-trip got %v, want %v", i, got, want)
		}
	}
}

func TestProtoUnmarshalText(t *testing.T) {
	var p Proto = 1
	err := p.UnmarshalText([]byte(nil))
	if err != nil || p != 0 {
		t.Fatalf("empty input, got err=%v, p=%v, want nil, 0", err, p)
	}

	for i := range 256 {
		var p Proto
		must.Do(p.UnmarshalText([]byte(fmt.Sprintf("%d", i))))
		if got, want := p, Proto(i); got != want {
			t.Errorf("Proto(%d) = %v, want %v", i, got, want)
		}
	}

	for name, wantProto := range acceptedNames {
		var p Proto
		must.Do(p.UnmarshalText([]byte(name)))
		if got, want := p, wantProto; got != want {
			t.Errorf("Proto(%q) = %v, want %v", name, got, want)
		}
	}

	for wantProto, name := range preferredNames {
		var p Proto
		must.Do(p.UnmarshalText([]byte(name)))
		if got, want := p, wantProto; got != want {
			t.Errorf("Proto(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestProtoMarshalText(t *testing.T) {
	for i := range 256 {
		text := must.Get(Proto(i).MarshalText())

		if wantName, ok := preferredNames[Proto(i)]; ok {
			if got, want := string(text), wantName; got != want {
				t.Errorf("Proto(%d).MarshalText() = %q, want preferred name %q", i, got, want)
			}
			continue
		}

		if got, want := string(text), fmt.Sprintf("%d", i); got != want {
			t.Errorf("Proto(%d).MarshalText() = %q, want %q", i, got, want)
		}
	}
}

func TestProtoMarshalJSON(t *testing.T) {
	for i := range 256 {
		j := must.Get(Proto(i).MarshalJSON())
		if got, want := string(j), fmt.Sprintf(`%d`, i); got != want {
			t.Errorf("Proto(%d).MarshalJSON() = %q, want %q", i, got, want)
		}
	}
}

func TestProtoUnmarshalJSON(t *testing.T) {
	var p Proto

	for i := range 256 {
		j := []byte(fmt.Sprintf(`%d`, i))
		must.Do(json.Unmarshal(j, &p))
		if got, want := p, Proto(i); got != want {
			t.Errorf("Proto(%d) = %v, want %v", i, got, want)
		}
	}

	for name, wantProto := range acceptedNames {
		must.Do(json.Unmarshal([]byte(fmt.Sprintf(`"%s"`, name)), &p))
		if got, want := p, wantProto; got != want {
			t.Errorf("Proto(%q) = %v, want %v", name, got, want)
		}
	}
}
