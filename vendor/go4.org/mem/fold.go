/*
Copyright 2020 The Go4 AUTHORS

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mem // import "go4.org/mem"

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// equalFoldRune compares a and b runes whether they fold equally.
//
// The code comes from strings.EqualFold, but shortened to only one rune.
func equalFoldRune(sr, tr rune) bool {
	if sr == tr {
		return true
	}
	// Make sr < tr to simplify what follows.
	if tr < sr {
		sr, tr = tr, sr
	}
	// Fast check for ASCII.
	if tr < utf8.RuneSelf && 'A' <= sr && sr <= 'Z' {
		// ASCII, and sr is upper case.  tr must be lower case.
		if tr == sr+'a'-'A' {
			return true
		}
		return false
	}

	// General case.  SimpleFold(x) returns the next equivalent rune > x
	// or wraps around to smaller values.
	r := unicode.SimpleFold(sr)
	for r != sr && r < tr {
		r = unicode.SimpleFold(r)
	}
	if r == tr {
		return true
	}
	return false
}

// HasPrefixFold is like HasPrefix but uses Unicode case-folding,
// matching case insensitively.
func HasPrefixFold(s, prefix RO) bool {
	if strings.HasPrefix(s.str(), prefix.str()) {
		// Exact case fast path.
		return true
	}
	for _, pr := range prefix.str() {
		if s.Len() == 0 {
			return false
		}
		// step with s, too
		sr, size := utf8.DecodeRuneInString(s.str())
		if sr == utf8.RuneError {
			return false
		}
		s = s.SliceFrom(size)
		if !equalFoldRune(sr, pr) {
			return false
		}
	}
	return true
}

// HasSuffixFold is like HasSuffix but uses Unicode case-folding,
// matching case insensitively.
func HasSuffixFold(s, suffix RO) bool {
	if suffix.Len() == 0 {
		return true
	}
	if strings.HasSuffix(s.str(), suffix.str()) {
		// Exact case fast path.
		return true
	}
	// count the runes and bytes in s, but only until rune count of suffix
	bo, so := s.Len(), suffix.Len()
	for bo > 0 && so > 0 {
		r, size := utf8.DecodeLastRuneInString(s.str()[:bo])
		if r == utf8.RuneError {
			return false
		}
		bo -= size

		sr, size := utf8.DecodeLastRuneInString(suffix.str()[:so])
		if sr == utf8.RuneError {
			return false
		}
		so -= size

		if !equalFoldRune(r, sr) {
			return false
		}
	}
	return so == 0
}

// ContainsFold is like Contains but uses Unicode case-folding for a case insensitive substring search.
func ContainsFold(s, substr RO) bool {
	if substr.Len() == 0 || strings.Contains(s.str(), substr.str()) {
		// Easy cases.
		return true
	}
	if s.Len() == 0 {
		return false
	}
	firstRune := rune(substr.At(0)) // Len != 0 checked above
	if firstRune >= utf8.RuneSelf {
		firstRune, _ = utf8.DecodeRuneInString(substr.str())
	}
	for i, rune := range s.str() {
		if equalFoldRune(rune, firstRune) && HasPrefixFold(s.SliceFrom(i), substr) {
			return true
		}
	}
	return false
}
