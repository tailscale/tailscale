// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cobs

import (
	"bytes"
	"fmt"

	"tailscale.com/util/must"
)

func Example() {
	// Frames is a list of frames that may contain null bytes.
	// Trivially joining the frames with a null byte would lead to
	// ambiguity when parsing as null bytes within the frame itself
	// cannot be distinguished from nulls used to mark frame boundaries.
	frames := [][]byte{
		[]byte("Hello world!"),
		[]byte(""),
		[]byte("\x00\x00\x00"),
		[]byte("Fizz\x00Buzz"),
	}

	// COBS encoding ensures that each frame never contains null bytes.
	for i, frame := range frames {
		frames[i] = AppendEncode(frame[:0], frame)
	}

	// Since the COBS-encoded frame lacks null bytes,
	// we can trivially join the frames together using a null byte.
	stream := bytes.Join(frames, []byte("\x00"))

	// Print out the COBS-encoded stream.
	fmt.Printf("COBS-encoded stream:\n\t%q\n\n", stream)

	// When decoding, the frame boundaries can be trivially detected
	// by splitting upon the null byte.
	frames = bytes.Split(stream, []byte("\x00"))

	// However, each individual frame is still COBS-encoded,
	// so we need to decode each one back to the original frame payload.
	for i, frame := range frames {
		frames[i] = must.Get(AppendDecode(frame[:0], frame))
	}

	// Print out each COBS-decoded frame to verify that it matches.
	fmt.Println("COBS-decoded frames:")
	for _, frame := range frames {
		fmt.Printf("\t%q\n", frame)
	}

	// Output:
	// COBS-encoded stream:
	// 	"\rHello world!\x00\x01\x00\x01\x01\x01\x01\x00\x05Fizz\x05Buzz"
	//
	// COBS-decoded frames:
	// 	"Hello world!"
	// 	""
	// 	"\x00\x00\x00"
	// 	"Fizz\x00Buzz"
}
