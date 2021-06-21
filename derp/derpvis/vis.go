// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"inet.af/netaddr"
	"tailscale.com/derp"
	"tailscale.com/types/key"
)

var DERPIP = flag.String("derp-ip", "", "IP address of DERP server to visualize")
var topN = flag.Int("n", 50, "How many processes to show at once")

func main() {
	flag.Parse()
	if *DERPIP == "" {
		log.Fatalf("Usage: derp-ip required")
	}

	derpIP := netaddr.MustParseIP(*DERPIP)
	url := fmt.Sprintf("http://%s/debug/traffic", derpIP.String())
	resp, err := http.Get(url)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	var mu sync.Mutex
	sent := &prioQueue{
		vals: map[key.Public]uint64{},
	}
	recv := &prioQueue{
		vals: map[key.Public]uint64{},
	}

	go func() {
		for {
			mu.Lock()
			sort.Sort(sent)
			sort.Sort(recv)
			for i := 0; i < min(*topN, recv.Len()); i++ {
				fmt.Printf("%d=(%s): recv=%d\n", i, recv.ord[i].ShortString(), recv.vals[recv.ord[i]])
			}
			mu.Unlock()
			time.Sleep(2 * time.Second)
		}
	}()

	dec := json.NewDecoder(resp.Body)
	var tmp derp.BytesSentRecv
	for err = dec.Decode(&tmp); err == nil; {
		mu.Lock()
		sent.Add(tmp.Key, tmp.Sent)
		recv.Add(tmp.Key, tmp.Recv)
		mu.Unlock()
	}
	log.Fatalf("Error decoding: %v", err)
}

type prioQueue struct {
	ord  []key.Public
	vals map[key.Public]uint64
}

func (p *prioQueue) Len() int           { return len(p.ord) }
func (p *prioQueue) Less(i, j int) bool { return p.vals[p.ord[i]] < p.vals[p.ord[j]] }
func (p *prioQueue) Swap(i, j int)      { p.ord[i], p.ord[j] = p.ord[j], p.ord[i] }
func (p *prioQueue) Add(key key.Public, val uint64) {
	if _, exists := p.vals[key]; exists {
		p.vals[key] += val
		return
	}
	p.vals[key] = val
	p.ord = append(p.ord, key)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
