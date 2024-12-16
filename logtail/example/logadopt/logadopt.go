// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command logadopt is a CLI tool to adopt a machine into a logtail collection.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func main() {
	collection := flag.String("c", "", "logtail collection name")
	publicID := flag.String("m", "", "machine public identifier")
	apiKey := flag.String("p", "", "logtail API key")
	flag.Parse()
	if len(flag.Args()) != 0 {
		flag.Usage()
		os.Exit(1)
	}
	log.SetFlags(0)

	req, err := http.NewRequest("POST", "https://log.tailscale.com/instances", strings.NewReader(url.Values{
		"collection": []string{*collection},
		"instances":  []string{*publicID},
		"adopt":      []string{"true"},
	}.Encode()))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(*apiKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("logadopt: response read failed %d: %v", resp.StatusCode, err)
	}
	if resp.StatusCode != 200 {
		log.Fatalf("adoption failed: %d: %s", resp.StatusCode, string(b))
	}
	log.Printf("%s", string(b))
}
