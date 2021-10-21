// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The wasmmod is a Tailscale-in-wasm proof of concept.
//
// See ../index.html and ../term.js for how it ties together.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall/js"
	"time"

	"github.com/skip2/go-qrcode"
	"tailscale.com/cmd/tailscale/cli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/net/packet"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/safesocket"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/filter"
	"tailscale.com/wgengine/netstack"
)

func main() {
	netns.SetEnabled(false)
	var logf logger.Logf = log.Printf

	dialer := new(tsdial.Dialer)
	eng, err := wgengine.NewUserspaceEngine(logf, wgengine.Config{
		Dialer: dialer,
	})
	if err != nil {
		log.Fatal(err)
	}

	tunDev, magicConn, dnsManager, ok := eng.(wgengine.InternalsGetter).GetInternals()
	if !ok {
		log.Fatalf("%T is not a wgengine.InternalsGetter", eng)
	}
	ns, err := netstack.Create(logf, tunDev, eng, magicConn, dialer, dnsManager)
	if err != nil {
		log.Fatalf("netstack.Create: %v", err)
	}
	ns.ProcessLocalIPs = true
	ns.ProcessSubnets = true
	ns.ForwardTCPIn = handleIncomingTCP
	if err := ns.Start(); err != nil {
		log.Fatalf("failed to start netstack: %v", err)
	}

	doc := js.Global().Get("document")
	state := doc.Call("getElementById", "state")
	topBar := doc.Call("getElementById", "topbar")
	topBarStyle := topBar.Get("style")
	netmapEle := doc.Call("getElementById", "netmap")
	loginEle := doc.Call("getElementById", "loginURL")

	netstackHandlePacket := tunDev.PostFilterIn
	tunDev.PostFilterIn = func(p *packet.Parsed, t *tstun.Wrapper) filter.Response {
		if p.IsEchoRequest() {
			go func() {
				topBarStyle.Set("background", "gray")
				time.Sleep(100 * time.Millisecond)
				topBarStyle.Set("background", "white")
			}()
		}
		return netstackHandlePacket(p, t)
	}

	var store ipn.StateStore = new(mem.Store)
	srv, err := ipnserver.New(log.Printf, "some-logid", store, eng, dialer, nil, ipnserver.Options{
		SurviveDisconnects: true,
	})
	if err != nil {
		log.Fatalf("ipnserver.New: %v", err)
	}
	lb := srv.LocalBackend()

	state.Set("innerHTML", "ready")

	lb.SetNotifyCallback(func(n ipn.Notify) {
		log.Printf("NOTIFY: %+v", n)
		if n.State != nil {
			state.Set("innerHTML", fmt.Sprint(*n.State))
			switch *n.State {
			case ipn.Running, ipn.Starting:
				loginEle.Set("innerHTML", "")
			}
		}
		if nm := n.NetMap; nm != nil {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "<p>Name: <b>%s</b></p>\n", html.EscapeString(nm.Name))
			fmt.Fprintf(&buf, "<p>Addresses: ")
			for i, a := range nm.Addresses {
				if i == 0 {
					fmt.Fprintf(&buf, "<b>%s</b>", a.IP())
				} else {
					fmt.Fprintf(&buf, ", %s", a.IP())
				}
			}
			fmt.Fprintf(&buf, "</p>")
			fmt.Fprintf(&buf, "<p>Machine: <b>%v</b>, %v</p>\n", nm.MachineStatus, nm.MachineKey)
			fmt.Fprintf(&buf, "<p>Nodekey: %v</p>\n", nm.NodeKey)
			fmt.Fprintf(&buf, "<hr><table>")
			for _, p := range nm.Peers {
				var ip string
				if len(p.Addresses) > 0 {
					ip = p.Addresses[0].IP().String()
				}
				fmt.Fprintf(&buf, "<tr><td>%s</td><td>%s</td></tr>\n", ip, html.EscapeString(p.Name))
			}
			fmt.Fprintf(&buf, "</table>")
			netmapEle.Set("innerHTML", buf.String())
		}
		if n.BrowseToURL != nil {
			esc := html.EscapeString(*n.BrowseToURL)
			pngBytes, _ := qrcode.Encode(*n.BrowseToURL, qrcode.Medium, 256)
			qrDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)
			loginEle.Set("innerHTML", fmt.Sprintf("<a href='%s' target=_blank>%s<br/><img src='%s' border=0></a>", esc, esc, qrDataURL))
		}
	})

	start := func() {
		err := lb.Start(ipn.Options{
			Prefs: &ipn.Prefs{
				// go run ./cmd/trunkd/  -remote-url=https://controlplane.tailscale.com
				//ControlURL:       "http://tsdev:8080",
				ControlURL:       "https://controlplane.tailscale.com",
				RouteAll:         false,
				AllowSingleHosts: true,
				WantRunning:      true,
				Hostname:         "wasm",
			},
		})
		log.Printf("Start error: %v", err)

	}

	js.Global().Set("startClicked", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		go start()
		return nil
	}))

	js.Global().Set("logoutClicked", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		log.Printf("Logout clicked")
		if lb.State() == ipn.NoState {
			log.Printf("Backend not running")
			return nil
		}
		go lb.Logout()
		return nil
	}))

	js.Global().Set("startLoginInteractive", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		log.Printf("State: %v", lb.State)

		go func() {
			if lb.State() == ipn.NoState {
				start()
			}
			lb.StartLoginInteractive()
		}()
		return nil
	}))

	js.Global().Set("seeGoroutines", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		full := make([]byte, 1<<20)
		buf := full[:runtime.Stack(full, true)]
		js.Global().Get("theTerminal").Call("reset")
		withCR := make([]byte, 0, len(buf)+bytes.Count(buf, []byte{'\n'}))
		for _, b := range buf {
			if b == '\n' {
				withCR = append(withCR, "\r\n"...)
			} else {
				withCR = append(withCR, b)
			}
		}
		js.Global().Get("theTerminal").Call("write", string(withCR))
		return nil
	}))

	js.Global().Set("startAuthKey", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		authKey := args[0].String()
		log.Printf("got auth key")
		go func() {
			err := lb.Start(ipn.Options{
				Prefs: &ipn.Prefs{
					// go run ./cmd/trunkd/  -remote-url=https://controlplane.tailscale.com
					//ControlURL:       "http://tsdev:8080",
					ControlURL:       "https://controlplane.tailscale.com",
					RouteAll:         false,
					AllowSingleHosts: true,
					WantRunning:      true,
					Hostname:         "wasm",
				},
				AuthKey: authKey,
			})
			log.Printf("Start error: %v", err)
		}()
		return nil
	}))

	var termOutOnce sync.Once

	js.Global().Set("runTailscaleCLI", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) < 1 {
			log.Printf("missing args")
			return nil
		}
		// TODO(bradfitz): enforce that we're only running one
		// CLI command at a time, as we modify package cli
		// globals below, like cli.Fatalf.

		go func() {
			if len(args) >= 2 {
				onDone := args[1]
				defer onDone.Invoke() // re-print the prompt
			}
			/*
				fs := js.Global().Get("globalThis").Get("fs")
				oldWriteSync := fs.Get("writeSync")
				defer fs.Set("writeSync", oldWriteSync)

				fs.Set("writeSync", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
					if len(args) != 2 {
						return nil
					}
					js.Global().Get("theTerminal").Call("write", fmt.Sprintf("Got a %T %v\r\n", args[1], args[1]))
					return nil
				}))
			*/
			line := args[0].String()
			f := strings.Fields(line)
			term := js.Global().Get("theTerminal")
			termOutOnce.Do(func() {
				cli.Stdout = termWriter{term}
				cli.Stderr = termWriter{term}
			})

			cli.Fatalf = func(format string, a ...interface{}) {
				term.Call("write", strings.ReplaceAll(fmt.Sprintf(format, a...), "\n", "\n\r"))
				runtime.Goexit()
			}

			// TODO(bradfitz): add a cli package global logger and make that
			// package use it, rather than messing with log.SetOutput.
			log.SetOutput(cli.Stderr)
			defer log.SetOutput(os.Stderr) // back to console

			defer func() {
				if e := recover(); e != nil {
					term.Call("write", fmt.Sprintf("%s\r\n", e))
					fmt.Fprintf(os.Stderr, "recovered panic from %q: %v", f, e)
				}
			}()

			if err := cli.Run(f[1:]); err != nil {
				fmt.Fprintf(os.Stderr, "CLI error on %q: %v\n", f, err)
				term.Call("write", fmt.Sprintf("%v\r\n", err))
				return
			}
		}()
		return nil
	}))

	js.Global().Set("runFakeCURL", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) < 2 {
			log.Printf("missing args")
			return nil
		}
		go func() {
			onDone := args[1]
			defer onDone.Invoke() // re-print the prompt

			line := args[0].String()
			f := strings.Fields(line)
			if len(f) < 2 {
				return
			}
			wantURL := f[1]

			term := js.Global().Get("theTerminal")

			c := &http.Client{
				Transport: &http.Transport{
					DialContext: dialer.UserDial,
				},
			}

			res, err := c.Get(wantURL)
			if err != nil {
				term.Call("write", fmt.Sprintf("Error: %v\r\n", err))
				return
			}
			defer res.Body.Close()
			res.Write(termWriter{term})
		}()
		return nil
	}))

	js.Global().Set("runSSH", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) < 2 {
			log.Printf("missing args")
			return nil
		}
		go func() {
			onDone := args[1]
			defer onDone.Invoke() // re-print the prompt

			line := args[0].String()
			f := strings.Fields(line)
			host := f[1]

			term := js.Global().Get("theTerminal")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := dialer.UserDial(ctx, "tcp", net.JoinHostPort(host, "22"))
			if err != nil {
				term.Call("write", fmt.Sprintf("Error: %v\r\n", err))
				return
			}
			defer c.Close()
			br := bufio.NewReader(c)
			greet, err := br.ReadString('\n')
			if err != nil {
				term.Call("write", fmt.Sprintf("Error: %v\r\n", err))
				return
			}
			term.Call("write", fmt.Sprintf("%v\r\n\r\nTODO(bradfitz): rest of the owl", strings.TrimSpace(greet)))
		}()
		return nil
	}))

	ln, _, err := safesocket.Listen("", 0)
	if err != nil {
		log.Fatal(err)
	}

	err = srv.Run(context.Background(), ln)
	log.Fatalf("ipnserver.Run exited: %v", err)
}

type termWriter struct {
	o js.Value
}

func (w termWriter) Write(p []byte) (n int, err error) {
	r := bytes.Replace(p, []byte("\n"), []byte("\n\r"), -1)
	w.o.Call("write", string(r))
	return len(p), nil
}

func handleIncomingTCP(c net.Conn, port uint16) {
	if port != 80 {
		log.Printf("incoming conn on port %v; closing", port)
		c.Close()
		return
	}
	log.Printf("incoming conn on port %v", port)
	s := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("Got HTTP request: %+v", r)
			if c := strings.TrimPrefix(r.URL.Path, "/"); c != "" {
				body := js.Global().Get("document").Get("body")
				body.Set("bgColor", c)
			}
		}),
	}
	err := s.Serve(&oneConnListener{conn: c})
	log.Printf("http.Serve: %v", err)
}

type dummyAddr string
type oneConnListener struct {
	conn net.Conn
}

func (l *oneConnListener) Accept() (c net.Conn, err error) {
	c = l.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	l.conn = nil
	return
}

func (l *oneConnListener) Close() error { return nil }

func (l *oneConnListener) Addr() net.Addr { return dummyAddr("unused-address") }

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
