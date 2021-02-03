// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgcfg

import (
	"reflect"
	"runtime"
	"testing"
)

func noError(t *testing.T, err error) bool {
	if err == nil {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Error at %s:%d: %#v", fn, line, err)
	return false
}

func equal(t *testing.T, expected, actual interface{}) bool {
	if reflect.DeepEqual(expected, actual) {
		return true
	}
	_, fn, line, _ := runtime.Caller(1)
	t.Errorf("Failed equals at %s:%d\nactual   %#v\nexpected %#v", fn, line, actual, expected)
	return false
}

func TestParseEndpoint(t *testing.T) {
	_, _, err := parseEndpoint("[192.168.42.0:]:51880")
	if err == nil {
		t.Error("Error was expected")
	}
	host, port, err := parseEndpoint("192.168.42.0:51880")
	if noError(t, err) {
		equal(t, "192.168.42.0", host)
		equal(t, uint16(51880), port)
	}
	host, port, err = parseEndpoint("test.wireguard.com:18981")
	if noError(t, err) {
		equal(t, "test.wireguard.com", host)
		equal(t, uint16(18981), port)
	}
	host, port, err = parseEndpoint("[2607:5300:60:6b0::c05f:543]:2468")
	if noError(t, err) {
		equal(t, "2607:5300:60:6b0::c05f:543", host)
		equal(t, uint16(2468), port)
	}
	_, _, err = parseEndpoint("[::::::invalid:18981")
	if err == nil {
		t.Error("Error was expected")
	}
}

func TestValidateEndpoints(t *testing.T) {
	tests := []struct {
		in   string
		want error
	}{
		{"", nil},
		{"1.2.3.4:5", nil},
		{"1.2.3.4:5,6.7.8.9:10", nil},
		{",", &ParseError{why: "Missing port from endpoint", offender: ""}},
	}
	for _, tt := range tests {
		got := validateEndpoints(tt.in)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%q = %#v (%s); want %#v (%s)", tt.in, got, got, tt.want, tt.want)
		}
	}
}
