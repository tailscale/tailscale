// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package deephash

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"math/bits"
	"math/rand"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"testing/quick"
	"time"

	qt "github.com/frankban/quicktest"
	"go4.org/mem"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
	"tailscale.com/util/deephash/testtype"
	"tailscale.com/util/hashx"
	"tailscale.com/version"
)

type appendBytes []byte

func (p appendBytes) AppendTo(b []byte) []byte {
	return append(b, p...)
}

type selfHasherValueRecv struct {
	emit uint64
}

func (s selfHasherValueRecv) Hash(h *hashx.Block512) {
	h.HashUint64(s.emit)
}

type selfHasherPointerRecv struct {
	emit uint64
}

func (s *selfHasherPointerRecv) Hash(h *hashx.Block512) {
	h.HashUint64(s.emit)
}

func TestHash(t *testing.T) {
	type tuple [2]any
	type iface struct{ X any }
	type scalars struct {
		I8   int8
		I16  int16
		I32  int32
		I64  int64
		I    int
		U8   uint8
		U16  uint16
		U32  uint32
		U64  uint64
		U    uint
		UP   uintptr
		F32  float32
		F64  float64
		C64  complex64
		C128 complex128
	}
	type MyBool bool
	type MyHeader tar.Header
	var zeroFloat64 float64
	tests := []struct {
		in     tuple
		wantEq bool
	}{
		{in: tuple{false, true}, wantEq: false},
		{in: tuple{true, true}, wantEq: true},
		{in: tuple{false, false}, wantEq: true},
		{
			in: tuple{
				scalars{-8, -16, -32, -64, -1234, 8, 16, 32, 64, 1234, 5678, 32.32, 64.64, 32 + 32i, 64 + 64i},
				scalars{-8, -16, -32, -64, -1234, 8, 16, 32, 64, 1234, 5678, 32.32, 64.64, 32 + 32i, 64 + 64i},
			},
			wantEq: true,
		},
		{in: tuple{scalars{I8: math.MinInt8}, scalars{I8: math.MinInt8 / 2}}, wantEq: false},
		{in: tuple{scalars{I16: math.MinInt16}, scalars{I16: math.MinInt16 / 2}}, wantEq: false},
		{in: tuple{scalars{I32: math.MinInt32}, scalars{I32: math.MinInt32 / 2}}, wantEq: false},
		{in: tuple{scalars{I64: math.MinInt64}, scalars{I64: math.MinInt64 / 2}}, wantEq: false},
		{in: tuple{scalars{I: -1234}, scalars{I: -1234 / 2}}, wantEq: false},
		{in: tuple{scalars{U8: math.MaxUint8}, scalars{U8: math.MaxUint8 / 2}}, wantEq: false},
		{in: tuple{scalars{U16: math.MaxUint16}, scalars{U16: math.MaxUint16 / 2}}, wantEq: false},
		{in: tuple{scalars{U32: math.MaxUint32}, scalars{U32: math.MaxUint32 / 2}}, wantEq: false},
		{in: tuple{scalars{U64: math.MaxUint64}, scalars{U64: math.MaxUint64 / 2}}, wantEq: false},
		{in: tuple{scalars{U: 1234}, scalars{U: 1234 / 2}}, wantEq: false},
		{in: tuple{scalars{UP: 5678}, scalars{UP: 5678 / 2}}, wantEq: false},
		{in: tuple{scalars{F32: 32.32}, scalars{F32: math.Nextafter32(32.32, 0)}}, wantEq: false},
		{in: tuple{scalars{F64: 64.64}, scalars{F64: math.Nextafter(64.64, 0)}}, wantEq: false},
		{in: tuple{scalars{F32: float32(math.NaN())}, scalars{F32: float32(math.NaN())}}, wantEq: true},
		{in: tuple{scalars{F64: float64(math.NaN())}, scalars{F64: float64(math.NaN())}}, wantEq: true},
		{in: tuple{scalars{C64: 32 + 32i}, scalars{C64: complex(math.Nextafter32(32, 0), 32)}}, wantEq: false},
		{in: tuple{scalars{C128: 64 + 64i}, scalars{C128: complex(math.Nextafter(64, 0), 64)}}, wantEq: false},
		{in: tuple{[]int(nil), []int(nil)}, wantEq: true},
		{in: tuple{[]int{}, []int(nil)}, wantEq: false},
		{in: tuple{[]int{}, []int{}}, wantEq: true},
		{in: tuple{[]string(nil), []string(nil)}, wantEq: true},
		{in: tuple{[]string{}, []string(nil)}, wantEq: false},
		{in: tuple{[]string{}, []string{}}, wantEq: true},
		{in: tuple{[]appendBytes{{}, {0, 0, 0, 0, 0, 0, 0, 1}}, []appendBytes{{}, {0, 0, 0, 0, 0, 0, 0, 1}}}, wantEq: true},
		{in: tuple{[]appendBytes{{}, {0, 0, 0, 0, 0, 0, 0, 1}}, []appendBytes{{0, 0, 0, 0, 0, 0, 0, 1}, {}}}, wantEq: false},
		{in: tuple{iface{MyBool(true)}, iface{MyBool(true)}}, wantEq: true},
		{in: tuple{iface{true}, iface{MyBool(true)}}, wantEq: false},
		{in: tuple{iface{MyHeader{}}, iface{MyHeader{}}}, wantEq: true},
		{in: tuple{iface{MyHeader{}}, iface{tar.Header{}}}, wantEq: false},
		{in: tuple{iface{&MyHeader{}}, iface{&MyHeader{}}}, wantEq: true},
		{in: tuple{iface{&MyHeader{}}, iface{&tar.Header{}}}, wantEq: false},
		{in: tuple{iface{[]map[string]MyBool{}}, iface{[]map[string]MyBool{}}}, wantEq: true},
		{in: tuple{iface{[]map[string]bool{}}, iface{[]map[string]MyBool{}}}, wantEq: false},
		{in: tuple{zeroFloat64, -zeroFloat64}, wantEq: false}, // Issue 4883 (false alarm)
		{in: tuple{[]any(nil), 0.0}, wantEq: false},           // Issue 4883
		{in: tuple{[]any(nil), uint8(0)}, wantEq: false},      // Issue 4883
		{in: tuple{nil, nil}, wantEq: true},                   // Issue 4883
		{
			in: func() tuple {
				i1 := 1
				i2 := 2
				v1 := [3]*int{&i1, &i2, &i1}
				v2 := [3]*int{&i1, &i2, &i2}
				return tuple{v1, v2}
			}(),
			wantEq: false,
		},
		{in: tuple{netip.Addr{}, netip.Addr{}}, wantEq: true},
		{in: tuple{netip.Addr{}, netip.AddrFrom4([4]byte{})}, wantEq: false},
		{in: tuple{netip.AddrFrom4([4]byte{}), netip.AddrFrom4([4]byte{})}, wantEq: true},
		{in: tuple{netip.AddrFrom4([4]byte{192, 168, 0, 1}), netip.AddrFrom4([4]byte{192, 168, 0, 1})}, wantEq: true},
		{in: tuple{netip.AddrFrom4([4]byte{192, 168, 0, 1}), netip.AddrFrom4([4]byte{192, 168, 0, 2})}, wantEq: false},
		{in: tuple{netip.AddrFrom4([4]byte{}), netip.AddrFrom16([16]byte{})}, wantEq: false},
		{in: tuple{netip.AddrFrom16([16]byte{}), netip.AddrFrom16([16]byte{})}, wantEq: true},
		{in: tuple{netip.AddrPort{}, netip.AddrPort{}}, wantEq: true},
		{in: tuple{netip.AddrPort{}, netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0)}, wantEq: false},
		{in: tuple{netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0), netip.AddrPortFrom(netip.AddrFrom4([4]byte{}), 0)}, wantEq: true},
		{in: tuple{netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1234), netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1234)}, wantEq: true},
		{in: tuple{netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1234), netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1235)}, wantEq: false},
		{in: tuple{netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1234), netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 168, 0, 2}), 1234)}, wantEq: false},
		{in: tuple{netip.Prefix{}, netip.Prefix{}}, wantEq: true},
		{in: tuple{netip.Prefix{}, netip.PrefixFrom(netip.Addr{}, 1)}, wantEq: true},
		{in: tuple{netip.Prefix{}, netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0)}, wantEq: false},
		{in: tuple{netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 1), netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 1)}, wantEq: true},
		{in: tuple{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1), netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1)}, wantEq: true},
		{in: tuple{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1), netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 0)}, wantEq: false},
		{in: tuple{netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), 1), netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 0, 2}), 1)}, wantEq: false},
		{in: tuple{netipx.IPRange{}, netipx.IPRange{}}, wantEq: true},
		{in: tuple{netipx.IPRange{}, netipx.IPRangeFrom(netip.AddrFrom4([4]byte{}), netip.AddrFrom16([16]byte{}))}, wantEq: false},
		{in: tuple{netipx.IPRangeFrom(netip.AddrFrom4([4]byte{}), netip.AddrFrom16([16]byte{})), netipx.IPRangeFrom(netip.AddrFrom4([4]byte{}), netip.AddrFrom16([16]byte{}))}, wantEq: true},
		{in: tuple{netipx.IPRangeFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), netip.AddrFrom4([4]byte{192, 168, 0, 100})), netipx.IPRangeFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), netip.AddrFrom4([4]byte{192, 168, 0, 100}))}, wantEq: true},
		{in: tuple{netipx.IPRangeFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), netip.AddrFrom4([4]byte{192, 168, 0, 100})), netipx.IPRangeFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), netip.AddrFrom4([4]byte{192, 168, 0, 101}))}, wantEq: false},
		{in: tuple{netipx.IPRangeFrom(netip.AddrFrom4([4]byte{192, 168, 0, 1}), netip.AddrFrom4([4]byte{192, 168, 0, 100})), netipx.IPRangeFrom(netip.AddrFrom4([4]byte{192, 168, 0, 2}), netip.AddrFrom4([4]byte{192, 168, 0, 100}))}, wantEq: false},
		{in: tuple{key.DiscoPublic{}, key.DiscoPublic{}}, wantEq: true},
		{in: tuple{key.DiscoPublic{}, key.DiscoPublicFromRaw32(mem.B(func() []byte {
			b := make([]byte, 32)
			b[0] = 1
			return b
		}()))}, wantEq: false},
		{in: tuple{key.NodePublic{}, key.NodePublic{}}, wantEq: true},
		{in: tuple{key.NodePublic{}, key.NodePublicFromRaw32(mem.B(func() []byte {
			b := make([]byte, 32)
			b[0] = 1
			return b
		}()))}, wantEq: false},
		{in: tuple{&selfHasherPointerRecv{}, &selfHasherPointerRecv{}}, wantEq: true},
		{in: tuple{(*selfHasherPointerRecv)(nil), (*selfHasherPointerRecv)(nil)}, wantEq: true},
		{in: tuple{(*selfHasherPointerRecv)(nil), &selfHasherPointerRecv{}}, wantEq: false},
		{in: tuple{&selfHasherPointerRecv{emit: 1}, &selfHasherPointerRecv{emit: 2}}, wantEq: false},
		{in: tuple{selfHasherValueRecv{emit: 1}, selfHasherValueRecv{emit: 2}}, wantEq: false},
		{in: tuple{selfHasherValueRecv{emit: 2}, selfHasherValueRecv{emit: 2}}, wantEq: true},
	}

	for _, tt := range tests {
		gotEq := Hash(&tt.in[0]) == Hash(&tt.in[1])
		if gotEq != tt.wantEq {
			t.Errorf("(Hash(%T %v) == Hash(%T %v)) = %v, want %v", tt.in[0], tt.in[0], tt.in[1], tt.in[1], gotEq, tt.wantEq)
		}
	}
}

// Tests that we actually hash map elements. Whoops.
func TestIssue4868(t *testing.T) {
	m1 := map[int]string{1: "foo"}
	m2 := map[int]string{1: "bar"}
	if Hash(&m1) == Hash(&m2) {
		t.Error("bogus")
	}
}

func TestIssue4871(t *testing.T) {
	m1 := map[string]string{"": "", "x": "foo"}
	m2 := map[string]string{}
	if h1, h2 := Hash(&m1), Hash(&m2); h1 == h2 {
		t.Errorf("bogus: h1=%x, h2=%x", h1, h2)
	}
}

func TestNilVsEmptymap(t *testing.T) {
	m1 := map[string]string(nil)
	m2 := map[string]string{}
	if h1, h2 := Hash(&m1), Hash(&m2); h1 == h2 {
		t.Errorf("bogus: h1=%x, h2=%x", h1, h2)
	}
}

func TestMapFraming(t *testing.T) {
	m1 := map[string]string{"foo": "", "fo": "o"}
	m2 := map[string]string{}
	if h1, h2 := Hash(&m1), Hash(&m2); h1 == h2 {
		t.Errorf("bogus: h1=%x, h2=%x", h1, h2)
	}
}

func TestQuick(t *testing.T) {
	initSeed()
	err := quick.Check(func(v, w map[string]string) bool {
		return (Hash(&v) == Hash(&w)) == reflect.DeepEqual(v, w)
	}, &quick.Config{MaxCount: 1000, Rand: rand.New(rand.NewSource(int64(seed)))})
	if err != nil {
		t.Fatalf("seed=%v, err=%v", seed, err)
	}
}

type IntThenByte struct {
	_ int
	_ byte
}

type TwoInts struct{ _, _ int }

type IntIntByteInt struct {
	i1, i2 int32
	b      byte // padding after
	i3     int32
}

func u8(n uint8) string   { return string([]byte{n}) }
func u32(n uint32) string { return string(binary.LittleEndian.AppendUint32(nil, n)) }
func u64(n uint64) string { return string(binary.LittleEndian.AppendUint64(nil, n)) }
func ux(n uint) string {
	if bits.UintSize == 32 {
		return u32(uint32(n))
	} else {
		return u64(uint64(n))
	}
}

func TestGetTypeHasher(t *testing.T) {
	switch runtime.GOARCH {
	case "amd64", "arm64", "arm", "386", "riscv64":
	default:
		// Test outputs below are specifically for little-endian machines.
		// Just skip everything else for now. Feel free to add more above if
		// you have the hardware to test and it's little-endian.
		t.Skipf("skipping on %v", runtime.GOARCH)
	}
	type typedString string
	var (
		someInt        = int('A')
		someComplex128 = complex128(1 + 2i)
		someIP         = netip.MustParseAddr("1.2.3.4")
	)
	tests := []struct {
		name  string
		val   any
		out   string
		out32 string // overwrites out if 32-bit
	}{
		{
			name: "int",
			val:  int(1),
			out:  ux(1),
		},
		{
			name: "int_negative",
			val:  int(-1),
			out:  ux(math.MaxUint),
		},
		{
			name: "int8",
			val:  int8(1),
			out:  "\x01",
		},
		{
			name: "float64",
			val:  float64(1.0),
			out:  "\x00\x00\x00\x00\x00\x00\xf0?",
		},
		{
			name: "float32",
			val:  float32(1.0),
			out:  "\x00\x00\x80?",
		},
		{
			name: "string",
			val:  "foo",
			out:  "\x03\x00\x00\x00\x00\x00\x00\x00foo",
		},
		{
			name: "typedString",
			val:  typedString("foo"),
			out:  "\x03\x00\x00\x00\x00\x00\x00\x00foo",
		},
		{
			name: "string_slice",
			val:  []string{"foo", "bar"},
			out:  "\x01\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00foo\x03\x00\x00\x00\x00\x00\x00\x00bar",
		},
		{
			name:  "int_slice",
			val:   []int{1, 0, -1},
			out:   "\x01\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
			out32: "\x01\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
		},
		{
			name: "struct",
			val: struct {
				a, b int
				c    uint16
			}{1, -1, 2},
			out:   "\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x02\x00",
			out32: "\x01\x00\x00\x00\xff\xff\xff\xff\x02\x00",
		},
		{
			name: "nil_int_ptr",
			val:  (*int)(nil),
			out:  "\x00",
		},
		{
			name:  "int_ptr",
			val:   &someInt,
			out:   "\x01A\x00\x00\x00\x00\x00\x00\x00",
			out32: "\x01A\x00\x00\x00",
		},
		{
			name: "nil_uint32_ptr",
			val:  (*uint32)(nil),
			out:  "\x00",
		},
		{
			name: "complex128_ptr",
			val:  &someComplex128,
			out:  "\x01\x00\x00\x00\x00\x00\x00\xf0?\x00\x00\x00\x00\x00\x00\x00@",
		},
		{
			name:  "packet_filter",
			val:   filterRules,
			out:   "\x01\x04\x00\x00\x00\x00\x00\x00\x00\x01\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00*\v\x00\x00\x00\x00\x00\x00\x0010.1.3.4/32\v\x00\x00\x00\x00\x00\x00\x0010.0.0.0/24\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x001.2.3.4/32\x01 \x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04!\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00foo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00",
			out32: "\x01\x04\x00\x00\x00\x00\x00\x00\x00\x01\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00*\v\x00\x00\x00\x00\x00\x00\x0010.1.3.4/32\v\x00\x00\x00\x00\x00\x00\x0010.0.0.0/24\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x001.2.3.4/32\x01 \x00\x00\x00\x01\x00\x02\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04!\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00foo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00",
		},
		{
			name: "netip.Addr",
			val:  netip.MustParseAddr("fe80::123%foo"),
			out:  u64(16+3) + u64(0x80fe) + u64(0x2301<<48) + "foo",
		},
		{
			name: "ptr-netip.Addr",
			val:  &someIP,
			out:  u8(1) + u64(4) + u32(0x04030201),
		},
		{
			name: "ptr-nil-netip.Addr",
			val:  (*netip.Addr)(nil),
			out:  "\x00",
		},
		{
			name: "time",
			val:  time.Unix(1234, 5678).In(time.UTC),
			out:  u64(1234) + u32(5678) + u32(0),
		},
		{
			name: "time_ptr", // addressable, as opposed to "time" test above
			val:  ptr.To(time.Unix(1234, 5678).In(time.UTC)),
			out:  u8(1) + u64(1234) + u32(5678) + u32(0),
		},
		{
			name: "time_ptr_via_unexported",
			val:  testtype.NewUnexportedAddressableTime(time.Unix(1234, 5678).In(time.UTC)),
			out:  u8(1) + u64(1234) + u32(5678) + u32(0),
		},
		{
			name: "time_ptr_via_unexported_value",
			val:  *testtype.NewUnexportedAddressableTime(time.Unix(1234, 5678).In(time.UTC)),
			out:  u64(1234) + u32(5678) + u32(0),
		},
		{
			name: "time_custom_zone",
			val:  time.Unix(1655311822, 0).In(time.FixedZone("FOO", -60*60)),
			out:  u64(1655311822) + u32(0) + u32(math.MaxUint32-60*60+1),
		},
		{
			name: "time_nil",
			val:  (*time.Time)(nil),
			out:  "\x00",
		},
		{
			name: "array_memhash",
			val:  [4]byte{1, 2, 3, 4},
			out:  "\x01\x02\x03\x04",
		},
		{
			name: "array_ptr_memhash",
			val:  ptr.To([4]byte{1, 2, 3, 4}),
			out:  "\x01\x01\x02\x03\x04",
		},
		{
			name: "ptr_to_struct_partially_memhashable",
			val: &struct {
				A int16
				B int16
				C *int
			}{5, 6, nil},
			out: "\x01\x05\x00\x06\x00\x00",
		},
		{
			name: "struct_partially_memhashable_but_cant_addr",
			val: struct {
				A int16
				B int16
				C *int
			}{5, 6, nil},
			out: "\x05\x00\x06\x00\x00",
		},
		{
			name: "array_elements",
			val:  [4]byte{1, 2, 3, 4},
			out:  "\x01\x02\x03\x04",
		},
		{
			name: "bool",
			val:  true,
			out:  "\x01",
		},
		{
			name: "IntIntByteInt",
			val:  IntIntByteInt{1, 2, 3, 4},
			out:  "\x01\x00\x00\x00\x02\x00\x00\x00\x03\x04\x00\x00\x00",
		},
		{
			name: "IntIntByteInt-canaddr",
			val:  &IntIntByteInt{1, 2, 3, 4},
			out:  "\x01\x01\x00\x00\x00\x02\x00\x00\x00\x03\x04\x00\x00\x00",
		},
		{
			name: "array-IntIntByteInt",
			val: [2]IntIntByteInt{
				{1, 2, 3, 4},
				{5, 6, 7, 8},
			},
			out: "\x01\x00\x00\x00\x02\x00\x00\x00\x03\x04\x00\x00\x00\x05\x00\x00\x00\x06\x00\x00\x00\a\b\x00\x00\x00",
		},
		{
			name: "array-IntIntByteInt-canaddr",
			val: &[2]IntIntByteInt{
				{1, 2, 3, 4},
				{5, 6, 7, 8},
			},
			out: "\x01\x01\x00\x00\x00\x02\x00\x00\x00\x03\x04\x00\x00\x00\x05\x00\x00\x00\x06\x00\x00\x00\a\b\x00\x00\x00",
		},
		{
			name:  "tailcfg.Node",
			val:   &tailcfg.Node{},
			out:   "ANY", // magic value; just check it doesn't fail to hash
			out32: "ANY",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := reflect.ValueOf(tt.val)
			va := reflect.New(rv.Type()).Elem()
			va.Set(rv)
			fn := lookupTypeHasher(va.Type())
			hb := &hashBuffer{Hash: sha256.New()}
			h := new(hasher)
			h.Block512.Hash = hb
			fn(h, pointerOf(va.Addr()))
			const ptrSize = 32 << uintptr(^uintptr(0)>>63)
			if tt.out32 != "" && ptrSize == 32 {
				tt.out = tt.out32
			}
			h.sum()
			if got := string(hb.B); got != tt.out && tt.out != "ANY" {
				t.Fatalf("got %q; want %q", got, tt.out)
			}
		})
	}
}

func TestSliceCycle(t *testing.T) {
	type S []S
	c := qt.New(t)

	a := make(S, 1) // cyclic graph of 1 node
	a[0] = a
	b := make(S, 1) // cyclic graph of 1 node
	b[0] = b
	ha := Hash(&a)
	hb := Hash(&b)
	c.Assert(ha, qt.Equals, hb)

	c1 := make(S, 1) // cyclic graph of 2 nodes
	c2 := make(S, 1) // cyclic graph of 2 nodes
	c1[0] = c2
	c2[0] = c1
	hc1 := Hash(&c1)
	hc2 := Hash(&c2)
	c.Assert(hc1, qt.Equals, hc2)
	c.Assert(ha, qt.Not(qt.Equals), hc1)
	c.Assert(hb, qt.Not(qt.Equals), hc2)

	c3 := make(S, 1) // graph of 1 node pointing to cyclic graph of 2 nodes
	c3[0] = c1
	hc3 := Hash(&c3)
	c.Assert(hc1, qt.Not(qt.Equals), hc3)

	c4 := make(S, 2) // cyclic graph of 3 nodes
	c5 := make(S, 2) // cyclic graph of 3 nodes
	c4[0] = nil
	c4[1] = c4
	c5[0] = c5
	c5[1] = nil
	hc4 := Hash(&c4)
	hc5 := Hash(&c5)
	c.Assert(hc4, qt.Not(qt.Equals), hc5) // cycle occurs through different indexes
}

func TestMapCycle(t *testing.T) {
	type M map[string]M
	c := qt.New(t)

	a := make(M) // cyclic graph of 1 node
	a["self"] = a
	b := make(M) // cyclic graph of 1 node
	b["self"] = b
	ha := Hash(&a)
	hb := Hash(&b)
	c.Assert(ha, qt.Equals, hb)

	c1 := make(M) // cyclic graph of 2 nodes
	c2 := make(M) // cyclic graph of 2 nodes
	c1["peer"] = c2
	c2["peer"] = c1
	hc1 := Hash(&c1)
	hc2 := Hash(&c2)
	c.Assert(hc1, qt.Equals, hc2)
	c.Assert(ha, qt.Not(qt.Equals), hc1)
	c.Assert(hb, qt.Not(qt.Equals), hc2)

	c3 := make(M) // graph of 1 node pointing to cyclic graph of 2 nodes
	c3["child"] = c1
	hc3 := Hash(&c3)
	c.Assert(hc1, qt.Not(qt.Equals), hc3)

	c4 := make(M) // cyclic graph of 3 nodes
	c5 := make(M) // cyclic graph of 3 nodes
	c4["0"] = nil
	c4["1"] = c4
	c5["0"] = c5
	c5["1"] = nil
	hc4 := Hash(&c4)
	hc5 := Hash(&c5)
	c.Assert(hc4, qt.Not(qt.Equals), hc5) // cycle occurs through different keys
}

func TestPointerCycle(t *testing.T) {
	type P *P
	c := qt.New(t)

	a := new(P) // cyclic graph of 1 node
	*a = a
	b := new(P) // cyclic graph of 1 node
	*b = b
	ha := Hash(&a)
	hb := Hash(&b)
	c.Assert(ha, qt.Equals, hb)

	c1 := new(P) // cyclic graph of 2 nodes
	c2 := new(P) // cyclic graph of 2 nodes
	*c1 = c2
	*c2 = c1
	hc1 := Hash(&c1)
	hc2 := Hash(&c2)
	c.Assert(hc1, qt.Equals, hc2)
	c.Assert(ha, qt.Not(qt.Equals), hc1)
	c.Assert(hb, qt.Not(qt.Equals), hc2)

	c3 := new(P) // graph of 1 node pointing to cyclic graph of 2 nodes
	*c3 = c1
	hc3 := Hash(&c3)
	c.Assert(hc1, qt.Not(qt.Equals), hc3)
}

func TestInterfaceCycle(t *testing.T) {
	type I struct{ v any }
	c := qt.New(t)

	a := new(I) // cyclic graph of 1 node
	a.v = a
	b := new(I) // cyclic graph of 1 node
	b.v = b
	ha := Hash(&a)
	hb := Hash(&b)
	c.Assert(ha, qt.Equals, hb)

	c1 := new(I) // cyclic graph of 2 nodes
	c2 := new(I) // cyclic graph of 2 nodes
	c1.v = c2
	c2.v = c1
	hc1 := Hash(&c1)
	hc2 := Hash(&c2)
	c.Assert(hc1, qt.Equals, hc2)
	c.Assert(ha, qt.Not(qt.Equals), hc1)
	c.Assert(hb, qt.Not(qt.Equals), hc2)

	c3 := new(I) // graph of 1 node pointing to cyclic graph of 2 nodes
	c3.v = c1
	hc3 := Hash(&c3)
	c.Assert(hc1, qt.Not(qt.Equals), hc3)
}

var sink Sum

// filterRules is a packet filter that has both everything populated (in its
// first element) and also a few entries that are the typical shape for regular
// packet filters as sent to clients.
var filterRules = []tailcfg.FilterRule{
	{
		SrcIPs: []string{"*", "10.1.3.4/32", "10.0.0.0/24"},
		DstPorts: []tailcfg.NetPortRange{{
			IP:    "1.2.3.4/32",
			Bits:  ptr.To(32),
			Ports: tailcfg.PortRange{First: 1, Last: 2},
		}},
		IPProto: []int{1, 2, 3, 4},
		CapGrant: []tailcfg.CapGrant{{
			Dsts: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")},
			Caps: []tailcfg.PeerCapability{"foo"},
		}},
	},
	{
		SrcIPs: []string{"foooooooooo"},
		DstPorts: []tailcfg.NetPortRange{{
			IP:    "baaaaaarrrrr",
			Ports: tailcfg.PortRange{First: 1, Last: 2},
		}},
	},
	{
		SrcIPs: []string{"foooooooooo"},
		DstPorts: []tailcfg.NetPortRange{{
			IP:    "baaaaaarrrrr",
			Ports: tailcfg.PortRange{First: 1, Last: 2},
		}},
	},
	{
		SrcIPs: []string{"foooooooooo"},
		DstPorts: []tailcfg.NetPortRange{{
			IP:    "baaaaaarrrrr",
			Ports: tailcfg.PortRange{First: 1, Last: 2},
		}},
	},
}

func BenchmarkHashPacketFilter(b *testing.B) {
	b.ReportAllocs()

	for range b.N {
		sink = Hash(&filterRules)
	}
}

func TestHashMapAcyclic(t *testing.T) {
	m := map[int]string{}
	for i := range 100 {
		m[i] = fmt.Sprint(i)
	}
	got := map[string]bool{}

	hb := &hashBuffer{Hash: sha256.New()}

	hash := lookupTypeHasher(reflect.TypeFor[map[int]string]())
	for range 20 {
		va := reflect.ValueOf(&m).Elem()
		hb.Reset()
		h := new(hasher)
		h.Block512.Hash = hb
		hash(h, pointerOf(va.Addr()))
		h.sum()
		if got[string(hb.B)] {
			continue
		}
		got[string(hb.B)] = true
	}
	if len(got) != 1 {
		t.Errorf("got %d results; want 1", len(got))
	}
}

func TestPrintArray(t *testing.T) {
	type T struct {
		X [32]byte
	}
	x := T{X: [32]byte{1: 1, 31: 31}}
	hb := &hashBuffer{Hash: sha256.New()}
	h := new(hasher)
	h.Block512.Hash = hb
	va := reflect.ValueOf(&x).Elem()
	hash := lookupTypeHasher(va.Type())
	hash(h, pointerOf(va.Addr()))
	h.sum()
	const want = "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f"
	if got := hb.B; string(got) != want {
		t.Errorf("wrong:\n got: %q\nwant: %q\n", got, want)
	}
}

func BenchmarkHashMapAcyclic(b *testing.B) {
	b.ReportAllocs()
	m := map[int]string{}
	for i := range 100 {
		m[i] = fmt.Sprint(i)
	}

	hb := &hashBuffer{Hash: sha256.New()}
	va := reflect.ValueOf(&m).Elem()
	hash := lookupTypeHasher(va.Type())

	h := new(hasher)
	h.Block512.Hash = hb

	for range b.N {
		h.Reset()
		hash(h, pointerOf(va.Addr()))
	}
}

func BenchmarkTailcfgNode(b *testing.B) {
	b.ReportAllocs()

	node := new(tailcfg.Node)
	for range b.N {
		sink = Hash(node)
	}
}

func TestExhaustive(t *testing.T) {
	seen := make(map[Sum]bool)
	for i := range 100000 {
		s := Hash(&i)
		if seen[s] {
			t.Fatalf("hash collision %v", i)
		}
		seen[s] = true
	}
}

// verify this doesn't loop forever, as it used to (Issue 2340)
func TestMapCyclicFallback(t *testing.T) {
	type T struct {
		M map[string]any
	}
	v := &T{
		M: map[string]any{},
	}
	v.M["m"] = v.M
	Hash(v)
}

func TestArrayAllocs(t *testing.T) {
	if version.IsRace() {
		t.Skip("skipping test under race detector")
	}

	// In theory, there should be no allocations. However, escape analysis on
	// certain architectures fails to detect that certain cases do not escape.
	// This discrepancy currently affects sha256.digest.Sum.
	// Measure the number of allocations in sha256 to ensure that Hash does
	// not allocate on top of its usage of sha256.
	// See https://golang.org/issue/48055.
	var b []byte
	h := sha256.New()
	want := int(testing.AllocsPerRun(1000, func() {
		b = h.Sum(b[:0])
	}))
	switch runtime.GOARCH {
	case "amd64", "arm64":
		want = 0 // ensure no allocations on popular architectures
	}

	type T struct {
		X [32]byte
	}
	x := &T{X: [32]byte{1: 1, 2: 2, 3: 3, 4: 4}}
	got := int(testing.AllocsPerRun(1000, func() {
		sink = Hash(x)
	}))
	if got > want {
		t.Errorf("allocs = %v; want %v", got, want)
	}
}

// Test for http://go/corp/6311 issue.
func TestHashThroughView(t *testing.T) {
	type sshPolicyOut struct {
		Rules []tailcfg.SSHRuleView
	}
	type mapResponseOut struct {
		SSHPolicy *sshPolicyOut
	}
	// Just test we don't panic:
	_ = Hash(&mapResponseOut{
		SSHPolicy: &sshPolicyOut{
			Rules: []tailcfg.SSHRuleView{
				(&tailcfg.SSHRule{
					RuleExpires: ptr.To(time.Unix(123, 0)),
				}).View(),
			},
		},
	})
}

func BenchmarkHashArray(b *testing.B) {
	b.ReportAllocs()
	type T struct {
		X [32]byte
	}
	x := &T{X: [32]byte{1: 1, 2: 2, 3: 3, 4: 4}}

	for range b.N {
		sink = Hash(x)
	}
}

// hashBuffer is a hash.Hash that buffers all written data.
type hashBuffer struct {
	hash.Hash
	B []byte
}

func (h *hashBuffer) Write(b []byte) (int, error) {
	n, err := h.Hash.Write(b)
	h.B = append(h.B, b[:n]...)
	return n, err
}
func (h *hashBuffer) Reset() {
	h.Hash.Reset()
	h.B = h.B[:0]
}

func FuzzTime(f *testing.F) {
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(0), false, "", 0)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(0), true, "", 0)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(0), true, "hello", 0)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(0), true, "", 1234)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(0), true, "hello", 1234)

	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(1), false, "", 0)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(1), true, "", 0)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(1), true, "hello", 0)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(1), true, "", 1234)
	f.Add(int64(0), int64(0), false, "", 0, int64(0), int64(1), true, "hello", 1234)

	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), false, "", 0, int64(math.MaxInt64), int64(math.MaxInt64), false, "", 0)
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), false, "", 0, int64(math.MaxInt64), int64(math.MaxInt64), true, "", 0)
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), false, "", 0, int64(math.MaxInt64), int64(math.MaxInt64), true, "hello", 0)
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), false, "", 0, int64(math.MaxInt64), int64(math.MaxInt64), true, "", 1234)
	f.Add(int64(math.MaxInt64), int64(math.MaxInt64), false, "", 0, int64(math.MaxInt64), int64(math.MaxInt64), true, "hello", 1234)

	f.Add(int64(math.MinInt64), int64(math.MinInt64), false, "", 0, int64(math.MinInt64), int64(math.MinInt64), false, "", 0)
	f.Add(int64(math.MinInt64), int64(math.MinInt64), false, "", 0, int64(math.MinInt64), int64(math.MinInt64), true, "", 0)
	f.Add(int64(math.MinInt64), int64(math.MinInt64), false, "", 0, int64(math.MinInt64), int64(math.MinInt64), true, "hello", 0)
	f.Add(int64(math.MinInt64), int64(math.MinInt64), false, "", 0, int64(math.MinInt64), int64(math.MinInt64), true, "", 1234)
	f.Add(int64(math.MinInt64), int64(math.MinInt64), false, "", 0, int64(math.MinInt64), int64(math.MinInt64), true, "hello", 1234)

	f.Fuzz(func(t *testing.T,
		s1, ns1 int64, loc1 bool, name1 string, off1 int,
		s2, ns2 int64, loc2 bool, name2 string, off2 int,
	) {
		t1 := time.Unix(s1, ns1)
		if loc1 {
			_ = t1.In(time.FixedZone(name1, off1))
		}
		t2 := time.Unix(s2, ns2)
		if loc2 {
			_ = t2.In(time.FixedZone(name2, off2))
		}
		got := Hash(&t1) == Hash(&t2)
		want := t1.Format(time.RFC3339Nano) == t2.Format(time.RFC3339Nano)
		if got != want {
			t.Errorf("time.Time(%s) == time.Time(%s) mismatches hash equivalent", t1.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
		}
	})
}

func FuzzAddr(f *testing.F) {
	f.Fuzz(func(t *testing.T,
		u1a, u1b uint64, zone1 string,
		u2a, u2b uint64, zone2 string,
	) {
		var b1, b2 [16]byte
		binary.LittleEndian.PutUint64(b1[:8], u1a)
		binary.LittleEndian.PutUint64(b1[8:], u1b)
		binary.LittleEndian.PutUint64(b2[:8], u2a)
		binary.LittleEndian.PutUint64(b2[8:], u2b)

		var ips [4]netip.Addr
		ips[0] = netip.AddrFrom4(*(*[4]byte)(b1[:]))
		ips[1] = netip.AddrFrom4(*(*[4]byte)(b2[:]))
		ips[2] = netip.AddrFrom16(b1)
		if zone1 != "" {
			ips[2] = ips[2].WithZone(zone1)
		}
		ips[3] = netip.AddrFrom16(b2)
		if zone2 != "" {
			ips[3] = ips[2].WithZone(zone2)
		}

		for _, ip1 := range ips[:] {
			for _, ip2 := range ips[:] {
				got := Hash(&ip1) == Hash(&ip2)
				want := ip1 == ip2
				if got != want {
					t.Errorf("netip.Addr(%s) == netip.Addr(%s) mismatches hash equivalent", ip1.String(), ip2.String())
				}
			}
		}
	})
}

func TestFilterFields(t *testing.T) {
	type T struct {
		A int
		B int
		C int
	}

	hashers := map[string]func(*T) Sum{
		"all": HasherForType[T](),
		"ac":  HasherForType[T](IncludeFields[T]("A", "C")),
		"b":   HasherForType[T](ExcludeFields[T]("A", "C")),
	}

	tests := []struct {
		hasher string
		a, b   T
		wantEq bool
	}{
		{"all", T{1, 2, 3}, T{1, 2, 3}, true},
		{"all", T{1, 2, 3}, T{0, 2, 3}, false},
		{"all", T{1, 2, 3}, T{1, 0, 3}, false},
		{"all", T{1, 2, 3}, T{1, 2, 0}, false},

		{"ac", T{0, 0, 0}, T{0, 0, 0}, true},
		{"ac", T{1, 0, 1}, T{1, 1, 1}, true},
		{"ac", T{1, 1, 1}, T{1, 1, 0}, false},

		{"b", T{0, 0, 0}, T{0, 0, 0}, true},
		{"b", T{1, 0, 1}, T{1, 1, 1}, false},
		{"b", T{1, 1, 1}, T{0, 1, 0}, true},
	}
	for _, tt := range tests {
		f, ok := hashers[tt.hasher]
		if !ok {
			t.Fatalf("bad test: unknown hasher %q", tt.hasher)
		}
		sum1 := f(&tt.a)
		sum2 := f(&tt.b)
		got := sum1 == sum2
		if got != tt.wantEq {
			t.Errorf("hasher %q, for %+v and %v, got equal = %v; want %v", tt.hasher, tt.a, tt.b, got, tt.wantEq)
		}
	}
}
