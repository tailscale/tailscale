// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package nocasemaps

import (
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	xmaps "golang.org/x/exp/maps"
)

func pair[A, B any](a A, b B) (out struct {
	A A
	B B
}) {
	out.A = a
	out.B = b
	return out
}

func Test(t *testing.T) {
	c := qt.New(t)
	m := make(map[string]int)
	Set(m, "hello", 1)
	c.Assert(m, qt.DeepEquals, map[string]int{"hello": 1})
	Set(m, "HeLlO", 2)
	c.Assert(m, qt.DeepEquals, map[string]int{"hello": 2})
	c.Assert(Get(m, "hello"), qt.Equals, 2)
	c.Assert(pair(GetOk(m, "hello")), qt.Equals, pair(2, true))
	c.Assert(Get(m, "HeLlO"), qt.Equals, 2)
	c.Assert(pair(GetOk(m, "HeLlO")), qt.Equals, pair(2, true))
	c.Assert(Get(m, "HELLO"), qt.Equals, 2)
	c.Assert(pair(GetOk(m, "HELLO")), qt.Equals, pair(2, true))
	c.Assert(Get(m, "missing"), qt.Equals, 0)
	c.Assert(pair(GetOk(m, "missing")), qt.Equals, pair(0, false))
	Set(m, "foo", 3)
	Set(m, "BAR", 4)
	Set(m, "bAz", 5)
	c.Assert(m, qt.DeepEquals, map[string]int{"hello": 2, "foo": 3, "bar": 4, "baz": 5})
	Delete(m, "foo")
	c.Assert(m, qt.DeepEquals, map[string]int{"hello": 2, "bar": 4, "baz": 5})
	Delete(m, "bar")
	c.Assert(m, qt.DeepEquals, map[string]int{"hello": 2, "baz": 5})
	Delete(m, "BAZ")
	c.Assert(m, qt.DeepEquals, map[string]int{"hello": 2})
	// test cases for AppendSliceElem with int slices
	appendTestInt := make(map[string][]int)
	Set(appendTestInt, "firsT", []int{7})
	c.Assert(appendTestInt, qt.DeepEquals, map[string][]int{"first": {7}})
	AppendSliceElem(appendTestInt, "firsT", 77)
	c.Assert(appendTestInt, qt.DeepEquals, map[string][]int{"first": {7, 77}})
	Set(appendTestInt, "SeCOnd", []int{56})
	c.Assert(appendTestInt, qt.DeepEquals, map[string][]int{"first": {7, 77}, "second": {56}})
	AppendSliceElem(appendTestInt, "seCOnd", 563, 23)
	c.Assert(appendTestInt, qt.DeepEquals, map[string][]int{"first": {7, 77}, "second": {56, 563, 23}})
	// test cases for AppendSliceElem with string slices
	appendTestString := make(map[string][]string)
	Set(appendTestString, "firsTSTRING", []string{"hi"})
	c.Assert(appendTestString, qt.DeepEquals, map[string][]string{"firststring": {"hi"}})
	AppendSliceElem(appendTestString, "firsTSTRING", "hello", "bye")
	c.Assert(appendTestString, qt.DeepEquals, map[string][]string{"firststring": {"hi", "hello", "bye"}})

}

var lowerTests = []struct{ in, want string }{
	{"", ""},
	{"abc", "abc"},
	{"AbC123", "abc123"},
	{"azAZ09_", "azaz09_"},
	{"longStrinGwitHmixofsmaLLandcAps", "longstringwithmixofsmallandcaps"},
	{"renan bastos 93 AOSDAJDJAIDJAIDAJIaidsjjaidijadsjiadjiOOKKO", "renan bastos 93 aosdajdjaidjaidajiaidsjjaidijadsjiadjiookko"},
	{"LONG\u2C6FSTRING\u2C6FWITH\u2C6FNONASCII\u2C6FCHARS", "long\u0250string\u0250with\u0250nonascii\u0250chars"},
	{"\u2C6D\u2C6D\u2C6D\u2C6D\u2C6D", "\u0251\u0251\u0251\u0251\u0251"}, // shrinks one byte per char
	{"A\u0080\U0010FFFF", "a\u0080\U0010FFFF"},                           // test utf8.RuneSelf and utf8.MaxRune
}

func TestAppendToLower(t *testing.T) {
	for _, tt := range lowerTests {
		got := string(appendToLower(nil, tt.in))
		if got != tt.want {
			t.Errorf("appendToLower(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func FuzzAppendToLower(f *testing.F) {
	for _, tt := range lowerTests {
		f.Add(tt.in)
	}
	f.Fuzz(func(t *testing.T, in string) {
		got := string(appendToLower(nil, in))
		want := strings.ToLower(in)
		if got != want {
			t.Errorf("appendToLower(%q) = %q, want %q", in, got, want)
		}
	})
}

var (
	testLower = "production-server"
	testUpper = "PRODUCTION-SERVER"
	testMap   = make(map[string]int)
	testValue = 5
	testSink  int
)

func Benchmark(b *testing.B) {
	for i, key := range []string{testLower, testUpper} {
		b.Run([]string{"Lower", "Upper"}[i], func(b *testing.B) {
			b.Run("Get", func(b *testing.B) {
				b.Run("Naive", func(b *testing.B) {
					b.ReportAllocs()
					for range b.N {
						testSink = testMap[strings.ToLower(key)]
					}
				})
				b.Run("NoCase", func(b *testing.B) {
					b.ReportAllocs()
					for range b.N {
						testSink = Get(testMap, key)
					}
				})
			})
			b.Run("Set", func(b *testing.B) {
				b.Run("Naive", func(b *testing.B) {
					b.ReportAllocs()
					testMap[strings.ToLower(key)] = testValue
					for range b.N {
						testMap[strings.ToLower(key)] = testValue
					}
					xmaps.Clear(testMap)
				})
				b.Run("NoCase", func(b *testing.B) {
					b.ReportAllocs()
					Set(testMap, key, testValue)
					for range b.N {
						Set(testMap, key, testValue)
					}
					xmaps.Clear(testMap)
				})
			})
			b.Run("Delete", func(b *testing.B) {
				b.Run("Naive", func(b *testing.B) {
					b.ReportAllocs()
					for range b.N {
						delete(testMap, strings.ToLower(key))
					}
				})
				b.Run("NoCase", func(b *testing.B) {
					b.ReportAllocs()
					for range b.N {
						Delete(testMap, key)
					}
				})
			})
		})
	}
}
