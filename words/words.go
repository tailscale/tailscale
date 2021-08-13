// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package words contains accessors for some nice words.
package words

import (
	"bytes"
	_ "embed"
	"strings"
	"sync"
)

//go:embed tails.txt
var tailsTxt []byte

//go:embed scales.txt
var scalesTxt []byte

var (
	once          sync.Once
	tails, scales []string
)

// Tails returns words about tails.
func Tails() []string {
	once.Do(initWords)
	return tails
}

// Scales returns words about scales.
func Scales() []string {
	once.Do(initWords)
	return scales
}

func initWords() {
	tails = parseWords(tailsTxt)
	scales = parseWords(scalesTxt)
}

func parseWords(txt []byte) []string {
	n := bytes.Count(txt, []byte{'\n'})
	ret := make([]string, 0, n)
	for len(txt) > 0 {
		word := txt
		i := bytes.IndexByte(txt, '\n')
		if i != -1 {
			word, txt = word[:i], txt[i+1:]
		}
		if word := strings.TrimSpace(string(word)); word != "" && word[0] != '#' {
			ret = append(ret, word)
		}
	}
	return ret
}
