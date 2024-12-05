// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The logtail program logs stdin.
package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"

	"tailscale.com/logtail"
	"tailscale.com/types/logid"
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

	var id logid.PrivateID
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
