// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import "testing"

func TestUrlOfListenAddr(t *testing.T) {
	t.Parallel()

	testTable := map[string]struct {
		addr     string
		expected string
	}{
		"TestLocalhost": {
			addr:     "localhost:8088",
			expected: "http://localhost:8088",
		},
		"TestNoHost": {
			addr:     ":8088",
			expected: "http://127.0.0.1:8088",
		},
		"TestExplicitHost": {
			addr:     "127.0.0.2:8088",
			expected: "http://127.0.0.2:8088",
		},
		"TestIPv6": {
			addr:     "[::1]:8088",
			expected: "http://[::1]:8088",
		},
	}

	for name, test := range testTable {
		t.Run(name, func(t *testing.T) {
			url := urlOfListenAddr(test.addr)
			if url != test.expected {
				t.Errorf("expected url: '%s', got: '%s'", test.expected, url)
			}
		})
	}
}
