// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

// IsStandard reports whether this is standard JSON
// by checking that there are no comments and no trailing commas.
func (v Value) IsStandard() bool {
	return v.isStandard()
}
func (v *Value) isStandard() bool {
	if !v.BeforeExtra.IsStandard() {
		return false
	}
	if comp, ok := v.Value.(composite); ok {
		if !comp.rangeValues((*Value).isStandard) {
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
	return !b.hasComment()
}
func (b Extra) hasComment() bool {
	return consumeWhitespace(b) < len(b)
}

// Minimize removes all whitespace, comments, and trailing commas from v,
// making it compliant with standard JSON per RFC 8259.
func (v *Value) Minimize() {
	v.minimize()
	v.UpdateOffsets()
}
func (v *Value) minimize() bool {
	v.BeforeExtra = nil
	if v2, ok := v.Value.(composite); ok {
		v2.rangeValues((*Value).minimize)
		setTrailingComma(v2, false)
		*v2.afterExtra() = nil
	}
	v.AfterExtra = nil
	return true
}

// Standardize strips any features specific to HuJSON from v,
// making it compliant with standard JSON per RFC 8259.
// All comments and trailing commas are replaced with a space character
// in order to preserve the original line numbers and byte offsets.
func (v *Value) Standardize() {
	v.standardize()
	v.UpdateOffsets() // should be noop if offsets are already correct
}
func (v *Value) standardize() bool {
	v.BeforeExtra.standardize()
	if comp, ok := v.Value.(composite); ok {
		comp.rangeValues((*Value).standardize)
		if last := comp.lastValue(); last != nil && last.AfterExtra != nil {
			*comp.afterExtra() = append(append(last.AfterExtra, ' '), *comp.afterExtra()...)
			last.AfterExtra = nil
		}
		comp.afterExtra().standardize()
	}
	v.AfterExtra.standardize()
	return true
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
