// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause
//go:build gofuzz

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
