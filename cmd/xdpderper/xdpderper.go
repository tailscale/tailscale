// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"tailscale.com/derp/xdp"
	"tailscale.com/tsweb"
)

var (
	flagDevice  = flag.String("device", "", "target device name")
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
	server, err := xdp.NewSTUNServer(&xdp.STUNServerConfig{
		DeviceName:      *flagDevice,
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
	tsweb.Debugger(mux)
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
