// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package jsonutil provides utilities to improve JSON performance.
// It includes an Unmarshal wrapper that amortizes allocated garbage over subsequent runs
// and a Bytes type to reduce allocations when unmarshalling a non-hex-encoded string into a []byte.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"sync"
)

// decoder is a re-usable json decoder.
type decoder struct {
	dec *json.Decoder
	r   *bytes.Reader
}

var readerPool = sync.Pool{
	New: func() any {
		return bytes.NewReader(nil)
	},
}

var decoderPool = sync.Pool{
	New: func() any {
		var d decoder
		d.r = readerPool.Get().(*bytes.Reader)
		d.dec = json.NewDecoder(d.r)
		return &d
	},
}

// Unmarshal is similar to encoding/json.Unmarshal.
// There are three major differences:
//
// On error, encoding/json.Unmarshal zeros v.
// This Unmarshal may leave partial data in v.
// Always check the error before using v!
// (Future improvements may remove this bug.)
//
// The errors they return don't always match perfectly.
// If you do error matching more precise than err != nil,
// don't use this Unmarshal.
//
// This Unmarshal allocates considerably less memory.
func Unmarshal(b []byte, v any) error {
	d := decoderPool.Get().(*decoder)
	d.r.Reset(b)
	off := d.dec.InputOffset()
	err := d.dec.Decode(v)
	d.r.Reset(nil) // don't keep a reference to b
	// In case of error, report the offset in this byte slice,
	// instead of in the totality of all bytes this decoder has processed.
	// It is not possible to make all errors match json.Unmarshal exactly,
	// but we can at least try.
	switch jsonerr := err.(type) {
	case *json.SyntaxError:
		jsonerr.Offset -= off
	case *json.UnmarshalTypeError:
		jsonerr.Offset -= off
	case nil:
		// json.Unmarshal fails if there's any extra junk in the input.
		// json.Decoder does not; see https://github.com/golang/go/issues/36225.
		// We need to check for anything left over in the buffer.
		if d.dec.More() {
			// TODO: Provide a better error message.
			// Unfortunately, we can't set the msg field.
			// The offset doesn't perfectly match json:
			// Ours is at the end of the valid data,
			// and theirs is at the beginning of the extra data after whitespace.
			// Close enough, though.
			err = &json.SyntaxError{Offset: d.dec.InputOffset() - off}

			// TODO: zero v. This is hard; see encoding/json.indirect.
		}
	}
	if err == nil {
		decoderPool.Put(d)
	} else {
		// There might be junk left in the decoder's buffer.
		// There's no way to flush it, no Reset method.
		// Abandoned the decoder but reuse the reader.
		readerPool.Put(d.r)
	}
	return err
}
