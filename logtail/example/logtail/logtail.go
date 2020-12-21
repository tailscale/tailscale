// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The logtail program logs stdin.
package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"

	"tailscale.com/logtail"
)

func main() {
	collection := flag.String("c", "", "logtail collection name")
	privateID := flag.String("k", "", "machine private identifier, 32-bytes in hex")
	flag.Parse()
	if len(flag.Args()) != 0 {
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(0)

	var id logtail.PrivateID
	if err := id.UnmarshalText([]byte(*privateID)); err != nil {
		log.Fatalf("logtail: bad -privateid: %v", err)
	}

	logger := logtail.NewLogger(logtail.Config{
		Collection: *collection,
		PrivateID:  id,
	}, log.Printf)
	log.SetOutput(io.MultiWriter(logger, os.Stdout))
	defer logger.Flush()
	defer log.Printf("logtail exited")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		log.Println(scanner.Text())
	}
}
