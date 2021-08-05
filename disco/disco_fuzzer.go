// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//go:build gofuzz
// +build gofuzz

package disco

func Fuzz(data []byte) int {
	m, _ := Parse(data)

	newBytes := m.AppendMarshal(data)
	parsedMarshall, _ := Parse(newBytes)

	if m != parsedMarshall {
		panic("Parsing error")
	}
	return 1
}
