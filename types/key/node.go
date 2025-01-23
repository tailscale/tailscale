// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package key

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"unique"

	"go4.org/mem"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"tailscale.com/types/structs"
)

const (
	// nodePrivateHexPrefix is the prefix used to identify a
	// hex-encoded node private key.
	//
	// This prefix name is a little unfortunate, in that it comes from
	// WireGuard's own key types, and we've used it for both key types
	// we persist to disk (machine and node keys). But we're stuck
	// with it for now, barring another round of tricky migration.
	nodePrivateHexPrefix = "privkey:"

	// nodePublicHexPrefix is the prefix used to identify a
	// hex-encoded node public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	nodePublicHexPrefix = "nodekey:"

	// nodePublicBinaryPrefix is the prefix used to identify a
	// binary-encoded node public key.
	nodePublicBinaryPrefix = "np"

	// NodePublicRawLen is the length in bytes of a NodePublic, when
	// serialized with AppendTo, Raw32 or WriteRawWithoutAllocating.
	NodePublicRawLen = 32
)

// NodePrivate is a node key, used for WireGuard tunnels and
// communication with DERP servers.
type NodePrivate struct {
	_ structs.Incomparable // because == isn't constant-time
	k [32]byte
}

// NewNode creates and returns a new node private key.
func NewNode() NodePrivate {
	var ret NodePrivate
	rand(ret.k[:])
	// WireGuard does its own clamping, so this would be unnecessary -
	// but we also use this key for DERP comms, which does require
	// clamping.
	clamp25519Private(ret.k[:])
	return ret
}

// NodePrivateFromRaw32 parses a 32-byte raw value as a NodePrivate.
//
// Deprecated: only needed to cast from legacy node private key types,
// do not add more uses unrelated to #3206.
func NodePrivateFromRaw32(raw mem.RO) NodePrivate {
	if raw.Len() != 32 {
		panic("input has wrong size")
	}
	var ret NodePrivate
	raw.Copy(ret.k[:])
	return ret
}

func ParseNodePrivateUntyped(raw mem.RO) (NodePrivate, error) {
	var ret NodePrivate
	if err := parseHex(ret.k[:], raw, mem.B(nil)); err != nil {
		return NodePrivate{}, err
	}
	return ret, nil
}

// IsZero reports whether k is the zero value.
func (k NodePrivate) IsZero() bool {
	return k.Equal(NodePrivate{})
}

// Equal reports whether k and other are the same key.
func (k NodePrivate) Equal(other NodePrivate) bool {
	return subtle.ConstantTimeCompare(k.k[:], other.k[:]) == 1
}

// Public returns the NodePublic for k.
// Panics if NodePrivate is zero.
func (k NodePrivate) Public() NodePublic {
	if k.IsZero() {
		panic("can't take the public key of a zero NodePrivate")
	}
	var pubk [32]byte
	curve25519.ScalarBaseMult(&pubk, &k.k)
	return nodePubFrom32(pubk)
}

// AppendText implements encoding.TextAppender.
func (k NodePrivate) AppendText(b []byte) ([]byte, error) {
	return appendHexKey(b, nodePrivateHexPrefix, k.k[:]), nil
}

// MarshalText implements encoding.TextMarshaler.
func (k NodePrivate) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// MarshalText implements encoding.TextUnmarshaler.
func (k *NodePrivate) UnmarshalText(b []byte) error {
	return parseHex(k.k[:], mem.B(b), mem.S(nodePrivateHexPrefix))
}

// SealTo wraps cleartext into a NaCl box (see
// golang.org/x/crypto/nacl) to p, authenticated from k, using a
// random nonce.
//
// The returned ciphertext is a 24-byte nonce concatenated with the
// box value.
func (k NodePrivate) SealTo(p NodePublic, cleartext []byte) (ciphertext []byte) {
	if k.IsZero() || p.IsZero() {
		panic("can't seal with zero keys")
	}
	var nonce [24]byte
	rand(nonce[:])
	pub := p.Raw32()
	return box.Seal(nonce[:], cleartext, &nonce, &pub, &k.k)
}

// OpenFrom opens the NaCl box ciphertext, which must be a value
// created by SealTo, and returns the inner cleartext if ciphertext is
// a valid box from p to k.
func (k NodePrivate) OpenFrom(p NodePublic, ciphertext []byte) (cleartext []byte, ok bool) {
	if k.IsZero() || p.IsZero() {
		panic("can't open with zero keys")
	}
	if len(ciphertext) < 24 {
		return nil, false
	}
	nonce := (*[24]byte)(ciphertext)
	pub := p.Raw32()
	return box.Open(nil, ciphertext[len(nonce):], nonce, &pub, &k.k)
}

func (k NodePrivate) UntypedHexString() string {
	return hex.EncodeToString(k.k[:])
}

// handleToZeros is a unique.Handle to a [32]byte of all zeros.
// Per the [NodePublic] field docs, this value must never be set
// in the 'h' field.
var handleToZeros = unique.Make([32]byte{})

// NodePublic is the public portion of a NodePrivate.
type NodePublic struct {
	// h is either a zero value (for a NodePublic of 32 zero bytes) or a valid
	// (non-nil) unique.Handle pointer to a 32-byte array.
	//
	// h must never be a pointer to the [32]byte zero value ([handleToZeros]),
	// else there would be two valid representations of all zeros that wouldn't
	// be equal
	h unique.Handle[[32]byte]
}

// Shard returns a uint8 number from a public key with
// mostly-uniform distribution, suitable for sharding.
func (p NodePublic) Shard() uint8 {
	// A 25519 public key isn't uniformly random, as it ultimately
	// corresponds to a point on the curve.
	// But we don't need perfectly uniformly-random, we need
	// good-enough-for-sharding random, so we haphazardly
	// combine raw values of the key to give us something sufficient.
	k := p.Raw32()
	s := uint8(k[31]) + uint8(k[30]) + uint8(k[20])
	return s ^ uint8(k[2]+k[12])
}

// Compare returns -1, 0, or 1, depending on whether p orders before p2,
// using bytes.Compare on the bytes of the public key.
func (p NodePublic) Compare(p2 NodePublic) int {
	k := p.Raw32()
	k2 := p2.Raw32()
	return bytes.Compare(k[:], k2[:])
}

// ParseNodePublicUntyped parses an untyped 64-character hex value
// as a NodePublic.
//
// Deprecated: this function is risky to use, because it cannot verify
// that the hex string was intended to be a NodePublic. This can
// lead to accidentally decoding one type of key as another. For new
// uses that don't require backwards compatibility with the untyped
// string format, please use MarshalText/UnmarshalText.
func ParseNodePublicUntyped(raw mem.RO) (NodePublic, error) {
	var a [32]byte
	if err := parseHex(a[:], raw, mem.B(nil)); err != nil {
		return NodePublic{}, err
	}
	return nodePubFrom32(a), nil
}

func nodePubFrom32(a [32]byte) NodePublic {
	h := unique.Make(a)
	if h == handleToZeros {
		return NodePublic{}
	}
	return NodePublic{h: h}
}

// NodePublicFromRaw32 parses a 32-byte raw value as a NodePublic.
//
// This should be used only when deserializing a NodePublic from a
// binary protocol.
func NodePublicFromRaw32(raw mem.RO) NodePublic {
	if raw.Len() != 32 {
		panic("input has wrong size")
	}
	var puba [32]byte
	raw.Copy(puba[:])
	return nodePubFrom32(puba)
}

// badOldPrefix is a nodekey/discokey prefix that, when base64'd, serializes
// with a "bad01" ("bad ol'", ~"bad old") prefix. It's used for expired node
// keys so when we debug a customer issue, the "bad01" can jump out to us. See:
//
//	https://github.com/tailscale/tailscale/issues/6932
var badOldPrefix = []byte{109, 167, 116, 213, 215, 116}

// NodePublicWithBadOldPrefix returns a copy of k with its leading public key
// bytes mutated such that it base64's to a ShortString of [bad01] ("bad ol'"
// [expired node key]).
func NodePublicWithBadOldPrefix(k NodePublic) NodePublic {
	var buf [32]byte
	k.AppendTo(buf[:0])
	copy(buf[:], badOldPrefix)
	return NodePublicFromRaw32(mem.B(buf[:]))
}

// IsZero reports whether k is the zero value.
func (k NodePublic) IsZero() bool {
	return k == NodePublic{}
}

var validZeroPublic = NodePublic{h: unique.Make([32]byte{})}

// ShortString returns the Tailscale conventional debug representation
// of a public key: the first five base64 digits of the key, in square
// brackets.
func (k NodePublic) ShortString() string {
	var z NodePublic
	if k == z {
		k = validZeroPublic
	}
	return debug32(k.Raw32())
}

// AppendTo appends k, serialized as a 32-byte binary value, to
// buf. Returns the new slice.
func (k NodePublic) AppendTo(buf []byte) []byte {
	a := k.Raw32()
	return append(buf, a[:]...)
}

// ReadRawWithoutAllocating initializes k with bytes read from br.
// The reading is done ~4x slower than io.ReadFull, but in exchange is
// allocation-free.
func (k *NodePublic) ReadRawWithoutAllocating(br *bufio.Reader) error {
	var z NodePublic
	if *k != z {
		return errors.New("refusing to read into non-zero NodePublic")
	}
	// This is ~4x slower than io.ReadFull, but using io.ReadFull
	// causes one extra alloc, which is significant for the DERP
	// server that consumes this method. So, process stuff slower but
	// without allocation.
	//
	// Dear future: if io.ReadFull stops causing stuff to escape, you
	// should switch back to that.
	var a [32]byte
	for i := range a {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		a[i] = b
	}
	*k = nodePubFrom32(a)
	return nil
}

// WriteRawWithoutAllocating writes out k as 32 bytes to bw.
// The writing is done ~3x slower than bw.Write, but in exchange is
// allocation-free.
func (k NodePublic) WriteRawWithoutAllocating(bw *bufio.Writer) error {
	// Equivalent to bw.Write(k.k[:]), but without causing an
	// escape-related alloc.
	//
	// Dear future: if bw.Write(k.k[:]) stops causing stuff to escape,
	// you should switch back to that.
	for _, b := range k.Raw32() {
		err := bw.WriteByte(b)
		if err != nil {
			return err
		}
	}
	return nil
}

// Raw32 returns k encoded as 32 raw bytes.
//
// Deprecated: only needed for a single legacy use in the control
// server and a few places in the wireguard-go API; don't add
// more uses.
func (k NodePublic) Raw32() [32]byte {
	if k.h == (unique.Handle[[32]byte]{}) {
		// TODO(bradfitz): add an IsValid method to unique.Handle.
		return [32]byte{}
	}
	return k.h.Value()
}

// Less reports whether k orders before other, using an undocumented
// deterministic ordering.
func (k NodePublic) Less(other NodePublic) bool {
	a, a2 := k.Raw32(), other.Raw32()
	return bytes.Compare(a[:], a2[:]) < 0
}

// UntypedHexString returns k, encoded as an untyped 64-character hex
// string.
//
// Deprecated: this function is risky to use, because it produces
// serialized values that do not identify themselves as a
// NodePublic, allowing other code to potentially parse it back in
// as the wrong key type. For new uses that don't require backwards
// compatibility with the untyped string format, please use
// MarshalText/UnmarshalText.
func (k NodePublic) UntypedHexString() string {
	a := k.Raw32()
	return hex.EncodeToString(a[:])
}

// String returns k as a hex-encoded string with a type prefix.
func (k NodePublic) String() string {
	bs, err := k.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(bs)
}

// AppendText implements encoding.TextAppender. It appends a typed prefix
// followed by hex encoded represtation of k to b.
func (k NodePublic) AppendText(b []byte) ([]byte, error) {
	a := k.Raw32()
	return appendHexKey(b, nodePublicHexPrefix, a[:]), nil
}

// MarshalText implements encoding.TextMarshaler. It returns a typed prefix
// followed by a hex encoded representation of k.
func (k NodePublic) MarshalText() ([]byte, error) {
	return k.AppendText(nil)
}

// UnmarshalText implements encoding.TextUnmarshaler. It expects a typed prefix
// followed by a hex encoded representation of k.
func (k *NodePublic) UnmarshalText(b []byte) error {
	var a [32]byte
	if err := parseHex(a[:], mem.B(b), mem.S(nodePublicHexPrefix)); err != nil {
		return err
	}
	*k = nodePubFrom32(a)
	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (k NodePublic) MarshalBinary() (data []byte, err error) {
	b := make([]byte, len(nodePublicBinaryPrefix)+NodePublicRawLen)
	copy(b[:len(nodePublicBinaryPrefix)], nodePublicBinaryPrefix)
	a := k.Raw32()
	copy(b[len(nodePublicBinaryPrefix):], a[:])
	return b, nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (k *NodePublic) UnmarshalBinary(in []byte) error {
	data := mem.B(in)
	if !mem.HasPrefix(data, mem.S(nodePublicBinaryPrefix)) {
		return fmt.Errorf("missing/incorrect type prefix %s", nodePublicBinaryPrefix)
	}
	if want, got := len(nodePublicBinaryPrefix)+NodePublicRawLen, data.Len(); want != got {
		return fmt.Errorf("incorrect len for NodePublic (%d != %d)", got, want)
	}
	var a [32]byte
	data.SliceFrom(len(nodePublicBinaryPrefix)).Copy(a[:])
	*k = nodePubFrom32(a)
	return nil
}

// WireGuardGoString prints k in the same format used by wireguard-go.
func (k NodePublic) WireGuardGoString() string {
	// This implementation deliberately matches the overly complicated
	// implementation in wireguard-go.
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	a := k.Raw32()
	b[first+0] = b64((a[0] >> 2) & 63)
	b[first+1] = b64(((a[0] << 4) | (a[1] >> 4)) & 63)
	b[first+2] = b64(((a[1] << 2) | (a[2] >> 6)) & 63)
	b[first+3] = b64(a[2] & 63)
	b[second+0] = b64(a[29] & 63)
	b[second+1] = b64((a[30] >> 2) & 63)
	b[second+2] = b64(((a[30] << 4) | (a[31] >> 4)) & 63)
	b[second+3] = b64((a[31] << 2) & 63)
	return string(b)
}
