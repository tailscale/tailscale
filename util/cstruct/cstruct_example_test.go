// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Only built on 64-bit platforms to avoid complexity

//go:build amd64 || arm64 || mips64le || ppc64le || riscv64
// +build amd64 arm64 mips64le ppc64le riscv64

package cstruct

import "fmt"

// This test provides a semi-realistic example of how you can
// use this package to decode a C structure.
func ExampleDecoder() {
	// Our example C structure:
	//    struct mystruct {
	//      char *p;
	//      char c;
	//	/* implicit: char _pad[3]; */
	//      int x;
	//    };
	//
	// The Go structure definition:
	type myStruct struct {
		Ptr    uintptr
		Ch     byte
		Intval uint32
	}

	// Our "in-memory" version of the above structure
	buf := []byte{
		1, 2, 3, 4, 0, 0, 0, 0, // ptr
		5,          // ch
		99, 99, 99, // padding
		78, 6, 0, 0, // x
	}
	d := NewDecoder(buf)

	// Decode the structure; if one of these function returns an error,
	// then subsequent decoder functions will return the zero value.
	var x myStruct
	x.Ptr = d.Uintptr()
	x.Ch = d.Byte()
	x.Intval = d.Uint32()

	// Note that per the Go language spec:
	//    [...] when evaluating the operands of an expression, assignment,
	//    or return statement, all function calls, method calls, and
	//    (channel) communication operations are evaluated in lexical
	//    left-to-right order
	//
	// Since each field is assigned via a function call, one could use the
	// following snippet to decode the struct.
	//     x := myStruct{
	//         Ptr:    d.Uintptr(),
	//         Ch:     d.Byte(),
	//         Intval: d.Uint32(),
	//     }
	//
	// However, this means that reordering the fields in the initialization
	// statement–normally a semantically identical operation–would change
	// the way the structure is parsed. Thus we do it as above with
	// explicit ordering.

	// After finishing with the decoder, check errors
	if err := d.Err(); err != nil {
		panic(err)
	}

	// Print the decoder offset and structure
	fmt.Printf("off=%d struct=%#v\n", d.Offset(), x)
	// Output: off=16 struct=cstruct.myStruct{Ptr:0x4030201, Ch:0x5, Intval:0x64e}
}
