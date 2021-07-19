// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

// UpdateOffsets iterates through v and updates all
// Value.StartOffset and Value.EndOffset fields so that they are accurate.
func (v *Value) UpdateOffsets() {
	v.updateOffsets(0)
}
func (v *Value) updateOffsets(n int) int {
	n += len(v.BeforeExtra)
	v.StartOffset = n
	switch v2 := v.Value.(type) {
	case Literal:
		n += len(v2)
	case *Object:
		n += len("{")
		for i := range v2.Members {
			n = v2.Members[i].Name.updateOffsets(n)
			n += len(":")
			n = v2.Members[i].Value.updateOffsets(n)
			n += len(",")
		}
		if v2.length() > 0 && !hasTrailingComma(v2) {
			n -= len(",")
		}
		n += len(v2.AfterExtra)
		n += len("}")
	case *Array:
		n += len("[")
		for i := range v2.Elements {
			n = v2.Elements[i].updateOffsets(n)
			n += len(",")
		}
		if v2.length() > 0 && !hasTrailingComma(v2) {
			n -= len(",")
		}
		n += len(v2.AfterExtra)
		n += len("]")
	}
	v.EndOffset = n
	n += len(v.AfterExtra)
	return n
}

// Pack serializes the value as HuJSON.
// The output is valid so long as every Extra and Literal in the Value is valid.
// The output does not alias the memory of any buffers referenced by v.
func (v Value) Pack() []byte {
	return v.append(nil)
}

// String is a string representation of v.
func (v Value) String() string {
	return string(v.append(nil))
}

func (v Value) append(b []byte) []byte {
	b = append(b, v.BeforeExtra...)
	switch v2 := v.Value.(type) {
	case Literal:
		b = append(b, v2...)
	case *Object:
		b = append(b, '{')
		for _, m := range v2.Members {
			b = m.Name.append(b)
			b = append(b, ':')
			b = m.Value.append(b)
			b = append(b, ',')
		}
		if v2.length() > 0 && !hasTrailingComma(v2) {
			b = b[:len(b)-1]
		}
		b = append(b, v2.AfterExtra...)
		b = append(b, '}')
	case *Array:
		b = append(b, '[')
		for _, e := range v2.Elements {
			b = e.append(b)
			b = append(b, ',')
		}
		if v2.length() > 0 && !hasTrailingComma(v2) {
			b = b[:len(b)-1]
		}
		b = append(b, v2.AfterExtra...)
		b = append(b, ']')
	}
	b = append(b, v.AfterExtra...)
	return b
}
