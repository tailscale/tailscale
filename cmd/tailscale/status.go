// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/peterbourgon/ff/v2/ffcli"
	"github.com/toqueteos/webbrowser"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/interfaces"
)

var statusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "status [-web] [-json]",
	ShortHelp:  "Show state of tailscaled and its connections",
	Exec:       runStatus,
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		fs.BoolVar(&statusArgs.json, "json", false, "output in JSON format (WARNING: format subject to change)")
		fs.BoolVar(&statusArgs.web, "web", false, "run webserver with HTML showing status")
		fs.StringVar(&statusArgs.listen, "listen", "127.0.0.1:8384", "listen address; use port 0 for automatic")
		fs.BoolVar(&statusArgs.browser, "browser", true, "Open a browser in web mode")
		return fs
	})(),
}

var statusArgs struct {
	json    bool   // JSON output mode
	web     bool   // run webserver
	listen  string // in web mode, webserver address to listen on, empty means auto
	browser bool   // in web mode, whether to open browser
}

func runStatus(ctx context.Context, args []string) error {
	c, bc, ctx, cancel := connect(ctx)
	defer cancel()

	bc.AllowVersionSkew = true

	ch := make(chan *ipnstate.Status, 1)
	bc.SetNotifyCallback(func(n ipn.Notify) {
		if n.ErrMessage != nil {
			log.Fatal(*n.ErrMessage)
		}
		if n.Status != nil {
			ch <- n.Status
		}
	})
	go pump(ctx, bc, c)

	getStatus := func() (*ipnstate.Status, error) {
		bc.RequestStatus()
		select {
		case st := <-ch:
			return st, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	st, err := getStatus()
	if err != nil {
		return err
	}
	if statusArgs.json {
		j, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return err
		}
		fmt.Printf("%s", j)
		return nil
	}
	if statusArgs.web {
		ln, err := net.Listen("tcp", statusArgs.listen)
		if err != nil {
			return err
		}
		statusURL := interfaces.HTTPOfListener(ln)
		fmt.Printf("Serving Tailscale status at %v ...\n", statusURL)
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		if statusArgs.browser {
			go webbrowser.Open(statusURL)
		}
		err = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.RequestURI != "/" {
				http.NotFound(w, r)
				return
			}
			st, err := getStatus()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			st.WriteHTML(w)
		}))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	var buf bytes.Buffer
	f := func(format string, a ...interface{}) { fmt.Fprintf(&buf, format, a...) }
	for _, peer := range st.Peers() {
		ps := st.Peer[peer]
		f("%s %-7s %-15s %-18s tx=%8d rx=%8d ",
			peer.ShortString(),
			ps.OS,
			ps.TailAddr,
			ps.SimpleHostName(),
			ps.TxBytes,
			ps.RxBytes,
		)
		for i, addr := range ps.Addrs {
			if i != 0 {
				f(", ")
			}
			if addr == ps.CurAddr {
				f("*%s*", addr)
			} else {
				f("%s", addr)
			}
		}
		f("\n")
	}
	os.Stdout.Write(buf.Bytes())
	return nil
}
