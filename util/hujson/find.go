// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package hujson

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Find locates the value specified by the JSON pointer (see RFC 6901).
// It returns nil if the value does not exist or the pointer is invalid.
// If a JSON object has multiple members matching a given name,
// the first is returned. Object names are matched exactly.
func (v *Value) Find(ptr string) *Value {
	// An empty pointer denotes the value itself.
	if ptr == "" {
		return v
	}

	// There must be one or more fragments.
	if !strings.HasPrefix(ptr, "/") {
		return nil
	}
	ptr = ptr[1:]
	var name string
	if i := strings.IndexByte(ptr, '/'); i >= 0 {
		name, ptr = ptr[:i], ptr[i:]
	} else {
		name, ptr = ptr, ""
	}

	// Unescape the name if necessary (section 4).
	if strings.IndexByte(name, '~') >= 0 {
		name = strings.ReplaceAll(name, "~1", "/")
		name = strings.ReplaceAll(name, "~0", "~")
	}

	// Index into the object or array.
	switch v := v.Value.(type) {
	case *Object:
		for i := range v.Members {
			if lit, ok := v.Members[i][0].Value.(Literal); ok && lit.equalString(name) {
				return v.Members[i][1].Find(ptr)
			}
		}
	case *Array:
		i, err := strconv.ParseUint(name, 10, 0)
		if err != nil || (i == 0 && name != "0") {
			return nil
		}
		if i < uint64(len(v.Elements)) {
			return v.Elements[i].Find(ptr)
		}
	}
	return nil
}

func (b Literal) equalString(s string) bool {
	// Fast-path: Assume there are no escape characters.
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' && bytes.IndexByte(b, '\\') < 0 {
		return string(b[len(`"`):len(b)-len(`"`)]) == s
	}
	// Slow-path: Unescape the string and then compare it.
	var s2 string
	return json.Unmarshal(b, &s2) == nil && s == s2
}
