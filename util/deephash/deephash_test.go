// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package deephash

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math"
	"math/rand"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"testing/quick"
	"time"
	"unsafe"

	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/structs"
	"tailscale.com/util/deephash/testtype"
	"tailscale.com/util/dnsname"
	"tailscale.com/version"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

type appendBytes []byte

func (p appendBytes) AppendTo(b []byte) []byte {
	return append(b, p...)
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
	}

	for _, tt := range tests {
		gotEq := Hash(tt.in[0]) == Hash(tt.in[1])
		if gotEq != tt.wantEq {
			t.Errorf("(Hash(%T %v) == Hash(%T %v)) = %v, want %v", tt.in[0], tt.in[0], tt.in[1], tt.in[1], gotEq, tt.wantEq)
		}
	}
}

func TestDeepHash(t *testing.T) {
	// v contains the types of values we care about for our current callers.
	// Mostly we're just testing that we don't panic on handled types.
	v := getVal()

	hash1 := Hash(v)
	t.Logf("hash: %v", hash1)
	for i := 0; i < 20; i++ {
		hash2 := Hash(getVal())
		if hash1 != hash2 {
			t.Error("second hash didn't match")
		}
	}
}

// Tests that we actually hash map elements. Whoops.
func TestIssue4868(t *testing.T) {
	m1 := map[int]string{1: "foo"}
	m2 := map[int]string{1: "bar"}
	if Hash(m1) == Hash(m2) {
		t.Error("bogus")
	}
}

func TestIssue4871(t *testing.T) {
	m1 := map[string]string{"": "", "x": "foo"}
	m2 := map[string]string{}
	if h1, h2 := Hash(m1), Hash(m2); h1 == h2 {
		t.Errorf("bogus: h1=%x, h2=%x", h1, h2)
	}
}

func TestNilVsEmptymap(t *testing.T) {
	m1 := map[string]string(nil)
	m2 := map[string]string{}
	if h1, h2 := Hash(m1), Hash(m2); h1 == h2 {
		t.Errorf("bogus: h1=%x, h2=%x", h1, h2)
	}
}

func TestMapFraming(t *testing.T) {
	m1 := map[string]string{"foo": "", "fo": "o"}
	m2 := map[string]string{}
	if h1, h2 := Hash(m1), Hash(m2); h1 == h2 {
		t.Errorf("bogus: h1=%x, h2=%x", h1, h2)
	}
}

func TestQuick(t *testing.T) {
	initSeed()
	err := quick.Check(func(v, w map[string]string) bool {
		return (Hash(v) == Hash(w)) == reflect.DeepEqual(v, w)
	}, &quick.Config{MaxCount: 1000, Rand: rand.New(rand.NewSource(int64(seed)))})
	if err != nil {
		t.Fatalf("seed=%v, err=%v", seed, err)
	}
}

func getVal() any {
	return &struct {
		WGConfig         *wgcfg.Config
		RouterConfig     *router.Config
		MapFQDNAddrs     map[dnsname.FQDN][]netip.Addr
		MapFQDNAddrPorts map[dnsname.FQDN][]netip.AddrPort
		MapDiscoPublics  map[key.DiscoPublic]bool
		MapResponse      *tailcfg.MapResponse
		FilterMatch      filter.Match
	}{
		&wgcfg.Config{
			Name:      "foo",
			Addresses: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom16([16]byte{3: 3}).Unmap(), 5)},
			Peers: []wgcfg.Peer{
				{
					PublicKey: key.NodePublic{},
				},
			},
		},
		&router.Config{
			Routes: []netip.Prefix{
				netip.MustParsePrefix("1.2.3.0/24"),
				netip.MustParsePrefix("1234::/64"),
			},
		},
		map[dnsname.FQDN][]netip.Addr{
			dnsname.FQDN("a."): {netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("4.3.2.1")},
			dnsname.FQDN("b."): {netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")},
			dnsname.FQDN("c."): {netip.MustParseAddr("6.6.6.6"), netip.MustParseAddr("7.7.7.7")},
			dnsname.FQDN("d."): {netip.MustParseAddr("6.7.6.6"), netip.MustParseAddr("7.7.7.8")},
			dnsname.FQDN("e."): {netip.MustParseAddr("6.8.6.6"), netip.MustParseAddr("7.7.7.9")},
			dnsname.FQDN("f."): {netip.MustParseAddr("6.9.6.6"), netip.MustParseAddr("7.7.7.0")},
		},
		map[dnsname.FQDN][]netip.AddrPort{
			dnsname.FQDN("a."): {netip.MustParseAddrPort("1.2.3.4:11"), netip.MustParseAddrPort("4.3.2.1:22")},
			dnsname.FQDN("b."): {netip.MustParseAddrPort("8.8.8.8:11"), netip.MustParseAddrPort("9.9.9.9:22")},
			dnsname.FQDN("c."): {netip.MustParseAddrPort("8.8.8.8:12"), netip.MustParseAddrPort("9.9.9.9:23")},
			dnsname.FQDN("d."): {netip.MustParseAddrPort("8.8.8.8:13"), netip.MustParseAddrPort("9.9.9.9:24")},
			dnsname.FQDN("e."): {netip.MustParseAddrPort("8.8.8.8:14"), netip.MustParseAddrPort("9.9.9.9:25")},
		},
		map[key.DiscoPublic]bool{
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 1, 31: 0})): true,
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 2, 31: 0})): false,
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 3, 31: 0})): true,
			key.DiscoPublicFromRaw32(mem.B([]byte{1: 4, 31: 0})): false,
		},
		&tailcfg.MapResponse{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[int]*tailcfg.DERPRegion{
					1: {
						RegionID:   1,
						RegionCode: "foo",
						Nodes: []*tailcfg.DERPNode{
							{
								Name:     "n1",
								RegionID: 1,
								HostName: "foo.com",
							},
							{
								Name:     "n2",
								RegionID: 1,
								HostName: "bar.com",
							},
						},
					},
				},
			},
			DNSConfig: &tailcfg.DNSConfig{
				Resolvers: []*dnstype.Resolver{
					{Addr: "10.0.0.1"},
				},
			},
			PacketFilter: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"1.2.3.4"},
					DstPorts: []tailcfg.NetPortRange{
						{
							IP:    "1.2.3.4/32",
							Ports: tailcfg.PortRange{First: 1, Last: 2},
						},
					},
				},
			},
			Peers: []*tailcfg.Node{
				{
					ID: 1,
				},
				{
					ID: 2,
				},
			},
			UserProfiles: []tailcfg.UserProfile{
				{ID: 1, LoginName: "foo@bar.com"},
				{ID: 2, LoginName: "bar@foo.com"},
			},
		},
		filter.Match{
			IPProto: []ipproto.Proto{1, 2, 3},
		},
	}
}

func TestTypeIsRecursive(t *testing.T) {
	type RecursiveStruct struct {
		v *RecursiveStruct
	}
	type RecursiveChan chan *RecursiveChan

	tests := []struct {
		val  any
		want bool
	}{
		{val: 42, want: false},
		{val: "string", want: false},
		{val: 1 + 2i, want: false},
		{val: struct{}{}, want: false},
		{val: (*RecursiveStruct)(nil), want: true},
		{val: RecursiveStruct{}, want: true},
		{val: time.Unix(0, 0), want: false},
		{val: structs.Incomparable{}, want: false}, // ignore its [0]func()
		{val: tailcfg.NetPortRange{}, want: false}, // uses structs.Incomparable
		{val: (*tailcfg.Node)(nil), want: false},
		{val: map[string]bool{}, want: false},
		{val: func() {}, want: false},
		{val: make(chan int), want: false},
		{val: unsafe.Pointer(nil), want: false},
		{val: make(RecursiveChan), want: true},
		{val: make(chan int), want: false},
	}
	for _, tt := range tests {
		got := typeIsRecursive(reflect.TypeOf(tt.val))
		if got != tt.want {
			t.Errorf("for type %T: got %v, want %v", tt.val, got, tt.want)
		}
	}
}

type IntThenByte struct {
	i int
	b byte
}

type TwoInts struct{ a, b int }

type IntIntByteInt struct {
	i1, i2 int32
	b      byte // padding after
	i3     int32
}

func TestCanMemHash(t *testing.T) {
	tests := []struct {
		val  any
		want bool
	}{
		{true, true},
		{uint(1), true},
		{uint8(1), true},
		{uint16(1), true},
		{uint32(1), true},
		{uint64(1), true},
		{uintptr(1), true},
		{int(1), true},
		{int8(1), true},
		{int16(1), true},
		{int32(1), true},
		{int64(1), true},
		{float32(1), true},
		{float64(1), true},
		{complex64(1), true},
		{complex128(1), true},
		{[32]byte{}, true},
		{func() {}, false},
		{make(chan int), false},
		{struct{ io.Writer }{nil}, false},
		{unsafe.Pointer(nil), false},
		{new(int), false},
		{TwoInts{}, true},
		{[4]TwoInts{}, true},
		{IntThenByte{}, false},
		{[4]IntThenByte{}, false},
		{tailcfg.PortRange{}, true},
		{int16(0), true},
		{struct {
			_ int
			_ int
		}{}, true},
		{struct {
			_ int
			_ uint8
			_ int
		}{}, false}, // gap
		{struct {
			_ structs.Incomparable // if not last, zero-width
			x int
		}{}, true},
		{struct {
			x int
			_ structs.Incomparable // zero-width last: has space, can't memhash
		}{},
			false},
		{[0]chan bool{}, true},
		{struct{ f [0]func() }{}, true},
	}
	for _, tt := range tests {
		got := canMemHash(reflect.TypeOf(tt.val))
		if got != tt.want {
			t.Errorf("for type %T: got %v, want %v", tt.val, got, tt.want)
		}
	}
}

func u8(n uint8) string   { return string([]byte{n}) }
func u16(n uint16) string { return string(binary.LittleEndian.AppendUint16(nil, n)) }
func u32(n uint32) string { return string(binary.LittleEndian.AppendUint32(nil, n)) }
func u64(n uint64) string { return string(binary.LittleEndian.AppendUint64(nil, n)) }

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
		want  bool // set true automatically if out != ""
		out   string
		out32 string // overwrites out if 32-bit
	}{
		{
			name: "int",
			val:  int(1),
			out:  "\x01\x00\x00\x00\x00\x00\x00\x00",
		},
		{
			name: "int_negative",
			val:  int(-1),
			out:  "\xff\xff\xff\xff\xff\xff\xff\xff",
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
			out:  "\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00foo\x03\x00\x00\x00\x00\x00\x00\x00bar",
		},
		{
			name:  "int_slice",
			val:   []int{1, 0, -1},
			out:   "\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff",
			out32: "\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff",
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
			out:   "\x04\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00*\v\x00\x00\x00\x00\x00\x00\x0010.1.3.4/32\v\x00\x00\x00\x00\x00\x00\x0010.0.0.0/24\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x001.2.3.4/32\x01 \x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x001.2.3.4/32\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00foo\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			out32: "\x04\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00*\v\x00\x00\x00\x00\x00\x00\x0010.1.3.4/32\v\x00\x00\x00\x00\x00\x00\x0010.0.0.0/24\x03\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x001.2.3.4/32\x01 \x00\x00\x00\x01\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\n\x00\x00\x00\x00\x00\x00\x001.2.3.4/32\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00foo\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\v\x00\x00\x00\x00\x00\x00\x00foooooooooo\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\f\x00\x00\x00\x00\x00\x00\x00baaaaaarrrrr\x00\x01\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		},
		{
			name: "netip.Addr",
			val:  netip.MustParseAddr("fe80::123%foo"),
			out:  "\r\x00\x00\x00\x00\x00\x00\x00fe80::123%foo",
		},
		{
			name: "ptr-netip.Addr",
			val:  &someIP,
			out:  "\x01\a\x00\x00\x00\x00\x00\x00\x001.2.3.4",
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
			val:  ptrTo(time.Unix(1234, 5678).In(time.UTC)),
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
			val:  ptrTo([4]byte{1, 2, 3, 4}),
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
			name: "IntIntByteInt-canddr",
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
			name: "tailcfg.Node",
			val:  &tailcfg.Node{},
			out:  "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + u64(uint64(time.Time{}.Unix())) + u32(0) + u32(0) + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + u64(uint64(time.Time{}.Unix())) + u32(0) + u32(0) + "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rv := reflect.ValueOf(tt.val)
			va := newAddressableValue(rv.Type())
			va.Set(rv)
			fn := getTypeInfo(va.Type()).hasher()
			hb := &hashBuffer{Hash: sha256.New()}
			h := new(hasher)
			h.Hash.H = hb
			got := fn(h, va)
			const ptrSize = 32 << uintptr(^uintptr(0)>>63)
			if tt.out32 != "" && ptrSize == 32 {
				tt.out = tt.out32
			}
			if tt.out != "" {
				tt.want = true
			}
			if got != tt.want {
				t.Fatalf("func returned %v; want %v", got, tt.want)
			}
			h.sum()
			if got := string(hb.B); got != tt.out {
				t.Fatalf("got %q; want %q", got, tt.out)
			}
		})
	}
}

var sink Sum

func BenchmarkHash(b *testing.B) {
	b.ReportAllocs()
	v := getVal()
	for i := 0; i < b.N; i++ {
		sink = Hash(v)
	}
}

func ptrTo[T any](v T) *T { return &v }

// filterRules is a packet filter that has both everything populated (in its
// first element) and also a few entries that are the typical shape for regular
// packet filters as sent to clients.
var filterRules = []tailcfg.FilterRule{
	{
		SrcIPs:  []string{"*", "10.1.3.4/32", "10.0.0.0/24"},
		SrcBits: []int{1, 2, 3},
		DstPorts: []tailcfg.NetPortRange{{
			IP:    "1.2.3.4/32",
			Bits:  ptrTo(32),
			Ports: tailcfg.PortRange{First: 1, Last: 2},
		}},
		IPProto: []int{1, 2, 3, 4},
		CapGrant: []tailcfg.CapGrant{{
			Dsts: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")},
			Caps: []string{"foo"},
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

	hash := HasherForType[*[]tailcfg.FilterRule]()
	for i := 0; i < b.N; i++ {
		sink = hash(&filterRules)
	}
}

func TestHashMapAcyclic(t *testing.T) {
	m := map[int]string{}
	for i := 0; i < 100; i++ {
		m[i] = fmt.Sprint(i)
	}
	got := map[string]bool{}

	hb := &hashBuffer{Hash: sha256.New()}

	ti := getTypeInfo(reflect.TypeOf(m))

	for i := 0; i < 20; i++ {
		v := addressableValue{reflect.ValueOf(&m).Elem()}
		hb.Reset()
		h := new(hasher)
		h.Hash.H = hb
		h.hashMap(v, ti, false)
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
	h.Hash.H = hb
	h.hashValue(addressableValue{reflect.ValueOf(&x).Elem()}, false)
	h.sum()
	const want = "\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f"
	if got := hb.B; string(got) != want {
		t.Errorf("wrong:\n got: %q\nwant: %q\n", got, want)
	}
}

func BenchmarkHashMapAcyclic(b *testing.B) {
	b.ReportAllocs()
	m := map[int]string{}
	for i := 0; i < 100; i++ {
		m[i] = fmt.Sprint(i)
	}

	hb := &hashBuffer{Hash: sha256.New()}
	v := addressableValue{reflect.ValueOf(&m).Elem()}
	ti := getTypeInfo(v.Type())

	h := new(hasher)
	h.Hash.H = hb

	for i := 0; i < b.N; i++ {
		h.Reset()
		h.hashMap(v, ti, false)
	}
}

func BenchmarkTailcfgNode(b *testing.B) {
	b.ReportAllocs()

	node := new(tailcfg.Node)
	for i := 0; i < b.N; i++ {
		sink = Hash(node)
	}
}

func TestExhaustive(t *testing.T) {
	seen := make(map[Sum]bool)
	for i := 0; i < 100000; i++ {
		s := Hash(i)
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
	// This discrepency currently affects sha256.digest.Sum.
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
					RuleExpires: ptrTo(time.Unix(123, 0)),
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

	for i := 0; i < b.N; i++ {
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
			t1.In(time.FixedZone(name1, off1))
		}
		t2 := time.Unix(s2, ns2)
		if loc2 {
			t2.In(time.FixedZone(name2, off2))
		}
		got := Hash(&t1) == Hash(&t2)
		want := t1.Format(time.RFC3339Nano) == t2.Format(time.RFC3339Nano)
		if got != want {
			t.Errorf("time.Time(%s) == time.Time(%s) mismatches hash equivalent", t1.Format(time.RFC3339Nano), t2.Format(time.RFC3339Nano))
		}
	})
}
