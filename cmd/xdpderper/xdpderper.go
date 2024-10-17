// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Command xdpderper runs the XDP STUN server.
package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"tailscale.com/derp/xdp"
	"tailscale.com/net/netutil"
	"tailscale.com/tsweb"
)

var (
	flagDevice  = flag.String("device", "", "target device name (default: autodetect)")
	flagPort    = flag.Int("dst-port", 0, "destination UDP port to serve")
	flagVerbose = flag.Bool("verbose", false, "verbose output including verifier errors")
	flagMode    = flag.String("mode", "xdp", "XDP mode; valid modes: [xdp, xdpgeneric, xdpdrv, xdpoffload]")
	flagHTTP    = flag.String("http", ":8230", "HTTP listen address")
)

func main() {
	flag.Parse()
	var attachFlags xdp.XDPAttachFlags
	switch strings.ToLower(*flagMode) {
	case "xdp":
		attachFlags = 0
	case "xdpgeneric":
		attachFlags = xdp.XDPGenericMode
	case "xdpdrv":
		attachFlags = xdp.XDPDriverMode
	case "xdpoffload":
		attachFlags = xdp.XDPOffloadMode
	default:
		log.Fatal("invalid mode")
	}
	deviceName := *flagDevice
	if deviceName == "" {
		var err error
		deviceName, _, err = netutil.DefaultInterfacePortable()
		if err != nil || deviceName == "" {
			log.Fatalf("failed to detect default route interface: %v", err)
		}
	}
	log.Printf("binding to device: %s", deviceName)

	server, err := xdp.NewSTUNServer(&xdp.STUNServerConfig{
		DeviceName:      deviceName,
		DstPort:         *flagPort,
		AttachFlags:     attachFlags,
		FullVerifierErr: *flagVerbose,
	})
	if err != nil {
		log.Fatalf("failed to init XDP STUN server: %v", err)
	}
	defer server.Close()
	err = prometheus.Register(server)
	if err != nil {
		log.Fatalf("failed to register XDP STUN server as a prometheus collector: %v", err)
	}
	log.Println("XDP STUN server started")

	mux := http.NewServeMux()
	debug := tsweb.Debugger(mux)
	debug.KVFunc("Drop STUN", func() any {
		return server.GetDropSTUN()
	})
	debug.Handle("drop-stun-on", "Drop STUN packets", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := server.SetDropSTUN(true)
		if err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			io.WriteString(w, "STUN packets are now being dropped.")
		}
	}))
	debug.Handle("drop-stun-off", "Handle STUN packets", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := server.SetDropSTUN(false)
		if err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			io.WriteString(w, "STUN packets are now being handled.")
		}
	}))
	errCh := make(chan error, 1)
	go func() {
		err := http.ListenAndServe(*flagHTTP, mux)
		errCh <- err
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		log.Printf("HTTP serve err: %v", err)
	case sig := <-sigCh:
		log.Printf("received signal: %s", sig)
	}

}
