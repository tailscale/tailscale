// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

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
		v2.setEmitTrailingComma(false)
		v2.setAfterExtra(nil)
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
		if last := comp.lastValue(); last != nil {
			if comp.getEmitTrailingComma() {
				last.AfterExtra = append(last.AfterExtra, ' ')
			}
			last.AfterExtra = append(last.AfterExtra, comp.getAfterExtra()...)
			comp.setAfterExtra(nil)
		}
		comp.setEmitTrailingComma(false)
		comp.getAfterExtra().standardize()
	}
	v.AfterExtra.standardize()
}
func (b Extra) standardize() {
	for i, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			// NOTE: Avoid changing '\n' to keep line numbers the same.
		default:
			b[i] = ' '
		}
	}
}
