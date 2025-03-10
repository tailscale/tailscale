// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	contents := fmt.Sprintf(`%d`, time.Now().UnixMilli())
	if err := os.WriteFile("mintime.txt", []byte(contents), 0644); err != nil {
		log.Fatal(err)
	}
}
