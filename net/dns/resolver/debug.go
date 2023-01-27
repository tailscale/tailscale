// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"fmt"
	"html"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/health"
)

func init() {
	health.RegisterDebugHandler("dnsfwd", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.FormValue("n"))
		if n <= 0 {
			n = 100
		} else if n > 10000 {
			n = 10000
		}
		fl := fwdLogAtomic.Load()
		if fl == nil || n != len(fl.ent) {
			fl = &fwdLog{ent: make([]fwdLogEntry, n)}
			fwdLogAtomic.Store(fl)
		}
		fl.ServeHTTP(w, r)
	}))
}

var fwdLogAtomic atomic.Pointer[fwdLog]

type fwdLog struct {
	mu  sync.Mutex
	pos int // ent[pos] is next entry
	ent []fwdLogEntry
}

type fwdLogEntry struct {
	Domain string
	Time   time.Time
}

func (fl *fwdLog) addName(name string) {
	if fl == nil {
		return
	}
	fl.mu.Lock()
	defer fl.mu.Unlock()
	if len(fl.ent) == 0 {
		return
	}
	fl.ent[fl.pos] = fwdLogEntry{Domain: name, Time: time.Now()}
	fl.pos++
	if fl.pos == len(fl.ent) {
		fl.pos = 0
	}
}

func (fl *fwdLog) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fl.mu.Lock()
	defer fl.mu.Unlock()

	fmt.Fprintf(w, "<html><h1>DNS forwards</h1>")
	now := time.Now()
	for i := 0; i < len(fl.ent); i++ {
		ent := fl.ent[(i+fl.pos)%len(fl.ent)]
		if ent.Domain == "" {
			continue
		}
		fmt.Fprintf(w, "%v ago: %v<br>\n", now.Sub(ent.Time).Round(time.Second), html.EscapeString(ent.Domain))
	}
}
