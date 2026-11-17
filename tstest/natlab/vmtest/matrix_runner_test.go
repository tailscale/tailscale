// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest_test

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

var (
	matrixTotal = flag.Bool("matrix-total", false,
		"print the total number of tests in the matrix and skip running them")
	matrixShard = flag.String("matrix-shard", "",
		"run only shard N of M, e.g. -matrix-shard=2/5 (1-indexed)")
)

func TestMatrix(t *testing.T) {
	if *matrixTotal {
		fmt.Printf("%d\n", len(testMatrix))
		return
	}

	tests := testMatrix[:]
	if *matrixShard != "" {
		parts := strings.Split(*matrixShard, "/")
		if len(parts) != 2 {
			t.Fatalf("-matrix-shard %q: expected format N/M", *matrixShard)
		}
		n, errN := strconv.Atoi(parts[0])
		m, errM := strconv.Atoi(parts[1])
		if errN != nil || errM != nil || n < 1 || n > m || m < 1 {
			t.Fatalf("-matrix-shard %q: N and M must be integers with 1 <= N <= M", *matrixShard)
		}
		// Distribute the tests as evenly as possible across shards without knowing
		// anything else about how the tests are configured.
		// TODO(cmol): Add filtering on:
		//   - MacOS tests only applies to macOS runners.
		//   - Name filter to split out OSes for build caches (FreeBSD is expensive).
		var sharded []struct {
			name string
			fn   func(t *testing.T)
		}
		for i, tt := range testMatrix {
			if i%m == n-1 {
				sharded = append(sharded, tt)
			}
		}
		tests = sharded
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}
