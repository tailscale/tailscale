// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The logreprocess program tails a log and reprocesses it.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"tailscale.com/logtail"
)

func main() {
	collection := flag.String("c", "", "logtail collection name to read")
	apiKey := flag.String("p", "", "logtail API key")
	timeout := flag.Duration("t", 0, "timeout after which logreprocess quits")
	flag.Parse()
	if len(flag.Args()) != 0 {
		flag.Usage()
		os.Exit(1)
	}
	log.SetFlags(0)

	if *timeout != 0 {
		go func() {
			<-time.After(*timeout)
			log.Printf("logreprocess: timeout reached, quitting")
			os.Exit(1)
		}()
	}

	req, err := http.NewRequest("GET", "https://log.tailscale.io/c/"+*collection+"?stream=true", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.SetBasicAuth(*apiKey, "")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("logreprocess: read error %d: %v", resp.StatusCode, err)
		}
		log.Fatalf("logreprocess: read error %d: %s", resp.StatusCode, string(b))
	}

	tracebackCache := make(map[logtail.PublicID]*ProcessedMsg)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var msg Msg
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			log.Fatalf("logreprocess of %q: %v", string(scanner.Bytes()), err)
		}
		var pMsg *ProcessedMsg
		if pMsg = tracebackCache[msg.Logtail.Instance]; pMsg != nil {
			pMsg.Text += "\n" + msg.Text
			if strings.HasPrefix(msg.Text, "Exception: ") {
				delete(tracebackCache, msg.Logtail.Instance)
			} else {
				continue // write later
			}
		} else {
			pMsg = &ProcessedMsg{
				OrigInstance: msg.Logtail.Instance,
				Text:         msg.Text,
			}
			pMsg.Logtail.ClientTime = msg.Logtail.ClientTime
		}

		if strings.HasPrefix(msg.Text, "Traceback (most recent call last):") {
			tracebackCache[msg.Logtail.Instance] = pMsg
			continue // write later
		}

		b, err := json.Marshal(pMsg)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s", b)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

type Msg struct {
	Logtail struct {
		Instance   logtail.PublicID `json:"instance"`
		ClientTime time.Time        `json:"client_time"`
	} `json:"logtail"`

	Text string `json:"text"`
}

type ProcessedMsg struct {
	Logtail struct {
		ClientTime time.Time `json:"client_time"`
	} `json:"logtail"`

	OrigInstance logtail.PublicID `json:"orig_instance"`
	Text         string           `json:"text"`
}
