// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The derpprobe binary probes derpers.
package main // import "tailscale.com/cmd/derper/derpprobe"

import (
	"fmt"
	"log"

	"tailscale.com/posture"
)

func main() {
	r, err := posture.Read()
	log.Printf("%+v", r)
	fmt.Println(err)
}
