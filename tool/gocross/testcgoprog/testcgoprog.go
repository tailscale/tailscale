// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

// /* Force use of cgo */
import "C"

import (
	"fmt"
	"runtime"
)

func main() {
	fmt.Println("testcgoprog", runtime.Version())
}
