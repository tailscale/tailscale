// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

// IsStandard reports whether this is standard JSON. It checks whether
// Extra only contains whitespace and that there are no trailing commas.
func (v *Value) IsStandard() bool {
	if !v.BeforeExtra.IsStandard() {
		return false
	}
	if comp, ok := v.Value.(composite); ok {
		if !comp.rangeValues(func(v *Value) bool { return v.IsStandard() }) {
			return false
		}
		if hasTrailingComma(comp) || !comp.afterExtra().IsStandard() {
			return false
		}
	}
	if !v.AfterExtra.IsStandard() {
		return false
	}
	return true
}

// IsStandard reports whether this is standard JSON whitespace.
func (b Extra) IsStandard() bool {
	return consumeWhitespace(b) == len(b)
}

// Minimize removes all whitespace, comments, and trailing commas from v,
// making it compliant with standard JSON per RFC 8259.
func (v *Value) Minimize() {
	v.minimize()
	v.UpdateOffsets()
}
func (v *Value) minimize() {
	v.BeforeExtra = nil
	if v2, ok := v.Value.(composite); ok {
		v2.rangeValues(func(v *Value) bool {
			v.minimize()
			return true
		})
		setTrailingComma(v2, false)
		*v2.afterExtra() = nil
	}
	v.AfterExtra = nil
}

// Standardize strips any features specific to HuJSON from v,
// making it compliant with standard JSON per RFC 8259.
// All comments and trailing commas are replaced with a space character
// in order to preserve the original line numbers and byte offsets.
func (v *Value) Standardize() {
	v.standardize()
	v.UpdateOffsets() // should be noop if offsets are already correct
}
func (v *Value) standardize() {
	v.BeforeExtra.standardize()
	if comp, ok := v.Value.(composite); ok {
		comp.rangeValues(func(v *Value) bool {
			v.standardize()
			return true
		})
		if last := comp.lastValue(); last != nil && last.AfterExtra != nil {
			*comp.afterExtra() = append(append(last.AfterExtra, ' '), *comp.afterExtra()...)
			last.AfterExtra = nil
		}
		comp.afterExtra().standardize()
	}
	v.AfterExtra.standardize()
}
func (b *Extra) standardize() {
	for i, c := range *b {
		switch c {
		case ' ', '\t', '\r', '\n':
			// NOTE: Avoid changing '\n' to keep line numbers the same.
		default:
			(*b)[i] = ' '
		}
	}
}
