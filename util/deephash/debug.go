// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build deephash_debug

package deephash

import "fmt"

func (h *hasher) HashBytes(b []byte) {
	fmt.Printf("B(%q)+", b)
	h.Block512.HashBytes(b)
}
func (h *hasher) HashString(s string) {
	fmt.Printf("S(%q)+", s)
	h.Block512.HashString(s)
}
func (h *hasher) HashUint8(n uint8) {
	fmt.Printf("U8(%d)+", n)
	h.Block512.HashUint8(n)
}
func (h *hasher) HashUint16(n uint16) {
	fmt.Printf("U16(%d)+", n)
	h.Block512.HashUint16(n)
}
func (h *hasher) HashUint32(n uint32) {
	fmt.Printf("U32(%d)+", n)
	h.Block512.HashUint32(n)
}
func (h *hasher) HashUint64(n uint64) {
	fmt.Printf("U64(%d)+", n)
	h.Block512.HashUint64(n)
}
func (h *hasher) Sum(b []byte) []byte {
	fmt.Println("FIN")
	return h.Block512.Sum(b)
}
