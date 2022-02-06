// Copyright 2020 The Inet.Af AUTHORS. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build gofuzz
// +build gofuzz

package netaddr

import (
	"bytes"
	"encoding"
	"fmt"
	"net"
	"reflect"
	"strings"
)

func Fuzz(b []byte) int {
	s := string(b)

	ip, _ := ParseIP(s)
	checkStringParseRoundTrip(ip, parseIP)
	checkEncoding(ip)

	// Check that we match the standard library's IP parser, modulo zones.
	if !strings.Contains(s, "%") {
		stdip := net.ParseIP(s)
		if ip.IsZero() != (stdip == nil) {
			fmt.Println("stdip=", stdip, "ip=", ip)
			panic("net.ParseIP nil != ParseIP zero")
		} else if !ip.IsZero() && !ip.Is4in6() && ip.String() != stdip.String() {
			fmt.Println("ip=", ip, "stdip=", stdip)
			panic("net.IP.String() != IP.String()")
		}
	}
	// Check that .Next().Prior() and .Prior().Next() preserve the IP.
	if !ip.IsZero() && !ip.Next().IsZero() && ip.Next().Prior() != ip {
		fmt.Println("ip=", ip, ".next=", ip.Next(), ".next.prior=", ip.Next().Prior())
		panic(".Next.Prior did not round trip")
	}
	if !ip.IsZero() && !ip.Prior().IsZero() && ip.Prior().Next() != ip {
		fmt.Println("ip=", ip, ".prior=", ip.Prior(), ".prior.next=", ip.Prior().Next())
		panic(".Prior.Next did not round trip")
	}

	port, err := ParseIPPort(s)
	if err == nil {
		checkStringParseRoundTrip(port, parseIPPort)
		checkEncoding(port)
	}
	port = IPPortFrom(ip, 80)
	checkStringParseRoundTrip(port, parseIPPort)
	checkEncoding(port)

	ipp, err := ParseIPPrefix(s)
	if err == nil {
		checkStringParseRoundTrip(ipp, parseIPPrefix)
		checkEncoding(ipp)
	}
	ipp = IPPrefixFrom(ip, 8)
	checkStringParseRoundTrip(ipp, parseIPPrefix)
	checkEncoding(ipp)

	return 0
}

// Hopefully some of these generic helpers will eventually make their way to the standard library.
// See https://github.com/golang/go/issues/46268.

// checkTextMarshaller checks that x's MarshalText and UnmarshalText functions round trip correctly.
func checkTextMarshaller(x encoding.TextMarshaler) {
	buf, err := x.MarshalText()
	if err == nil {
		return
	}
	y := reflect.New(reflect.TypeOf(x)).Interface().(encoding.TextUnmarshaler)
	err = y.UnmarshalText(buf)
	if err != nil {
		fmt.Printf("(%v).MarshalText() = %q\n", x, buf)
		panic(fmt.Sprintf("(%T).UnmarshalText(%q) = %v", y, buf, err))
	}
	if !reflect.DeepEqual(x, y) {
		fmt.Printf("(%v).MarshalText() = %q\n", x, buf)
		fmt.Printf("(%T).UnmarshalText(%q) = %v", y, buf, y)
		panic(fmt.Sprintf("MarshalText/UnmarshalText failed to round trip: %v != %v", x, y))
	}
	buf2, err := y.(encoding.TextMarshaler).MarshalText()
	if err != nil {
		fmt.Printf("(%v).MarshalText() = %q\n", x, buf)
		fmt.Printf("(%T).UnmarshalText(%q) = %v", y, buf, y)
		panic(fmt.Sprintf("failed to MarshalText a second time: %v", err))
	}
	if !bytes.Equal(buf, buf2) {
		fmt.Printf("(%v).MarshalText() = %q\n", x, buf)
		fmt.Printf("(%T).UnmarshalText(%q) = %v", y, buf, y)
		fmt.Printf("(%v).MarshalText() = %q\n", y, buf2)
		panic(fmt.Sprintf("second MarshalText differs from first: %q != %q", buf, buf2))
	}
}

// checkBinaryMarshaller checks that x's MarshalText and UnmarshalText functions round trip correctly.
func checkBinaryMarshaller(x encoding.BinaryMarshaler) {
	buf, err := x.MarshalBinary()
	if err == nil {
		return
	}
	y := reflect.New(reflect.TypeOf(x)).Interface().(encoding.BinaryUnmarshaler)
	err = y.UnmarshalBinary(buf)
	if err != nil {
		fmt.Printf("(%v).MarshalBinary() = %q\n", x, buf)
		panic(fmt.Sprintf("(%T).UnmarshalBinary(%q) = %v", y, buf, err))
	}
	if !reflect.DeepEqual(x, y) {
		fmt.Printf("(%v).MarshalBinary() = %q\n", x, buf)
		fmt.Printf("(%T).UnmarshalBinary(%q) = %v", y, buf, y)
		panic(fmt.Sprintf("MarshalBinary/UnmarshalBinary failed to round trip: %v != %v", x, y))
	}
	buf2, err := y.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		fmt.Printf("(%v).MarshalBinary() = %q\n", x, buf)
		fmt.Printf("(%T).UnmarshalBinary(%q) = %v", y, buf, y)
		panic(fmt.Sprintf("failed to MarshalBinary a second time: %v", err))
	}
	if !bytes.Equal(buf, buf2) {
		fmt.Printf("(%v).MarshalBinary() = %q\n", x, buf)
		fmt.Printf("(%T).UnmarshalBinary(%q) = %v", y, buf, y)
		fmt.Printf("(%v).MarshalBinary() = %q\n", y, buf2)
		panic(fmt.Sprintf("second MarshalBinary differs from first: %q != %q", buf, buf2))
	}
}

// fuzzAppendMarshaler is identical to appendMarshaler, defined in netaddr_test.go.
// We have two because the two go-fuzz implementations differ
// in whether they include _test.go files when typechecking.
// We need this fuzz file to compile with and without netaddr_test.go,
// which means defining the interface twice.
type fuzzAppendMarshaler interface {
	encoding.TextMarshaler
	AppendTo([]byte) []byte
}

// checkTextMarshalMatchesAppendTo checks that x's MarshalText matches x's AppendTo.
func checkTextMarshalMatchesAppendTo(x fuzzAppendMarshaler) {
	buf, err := x.MarshalText()
	if err != nil {
		panic(err)
	}
	buf2 := make([]byte, 0, len(buf))
	buf2 = x.AppendTo(buf2)
	if !bytes.Equal(buf, buf2) {
		panic(fmt.Sprintf("%v: MarshalText = %q, AppendTo = %q", x, buf, buf2))
	}
}

// parseType are trampoline functions that give ParseType functions the same signature.
// This would be nicer with generics.
func parseIP(s string) (interface{}, error)       { return ParseIP(s) }
func parseIPPort(s string) (interface{}, error)   { return ParseIPPort(s) }
func parseIPPrefix(s string) (interface{}, error) { return ParseIPPrefix(s) }

func checkStringParseRoundTrip(x fmt.Stringer, parse func(string) (interface{}, error)) {
	v, vok := x.(interface{ IsValid() bool })
	if vok && !v.IsValid() {
		// Ignore invalid values.
		return
	}
	// Zero values tend to print something like "invalid <TYPE>", so it's OK if they don't round trip.
	// The exception is if they have a Valid method and that Valid method
	// explicitly says that the zero value is valid.
	z, zok := x.(interface{ IsZero() bool })
	if zok && z.IsZero() && !(vok && v.IsValid()) {
		return
	}
	s := x.String()
	y, err := parse(s)
	if err != nil {
		panic(fmt.Sprintf("s=%q err=%v", s, err))
	}
	if !reflect.DeepEqual(x, y) {
		fmt.Printf("s=%q x=%#v y=%#v\n", s, x, y)
		panic(fmt.Sprintf("%T round trip identity failure", x))
	}
	s2 := y.(fmt.Stringer).String()
	if s != s2 {
		fmt.Printf("s=%#v s2=%#v\n", s, s2)
		panic(fmt.Sprintf("%T String round trip identity failure", x))
	}
}

func checkEncoding(x interface{}) {
	if tm, ok := x.(encoding.TextMarshaler); ok {
		checkTextMarshaller(tm)
	}
	if bm, ok := x.(encoding.BinaryMarshaler); ok {
		checkBinaryMarshaller(bm)
	}
	if am, ok := x.(fuzzAppendMarshaler); ok {
		checkTextMarshalMatchesAppendTo(am)
	}
}

// TODO: add helpers that check that String matches MarshalText for non-zero-ish values
