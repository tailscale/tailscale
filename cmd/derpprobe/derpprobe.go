// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The derpprobe binary probes derpers.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"time"

	"tailscale.com/prober"
	"tailscale.com/tsweb"
	"tailscale.com/version"
)

var (
	derpMapURL         = flag.String("derp-map", "https://login.tailscale.com/derpmap/default", "URL to DERP map (https:// or file://) or 'local' to use the local tailscaled's DERP map")
	versionFlag        = flag.Bool("version", false, "print version and exit")
	listen             = flag.String("listen", ":8030", "HTTP listen address")
	probeOnce          = flag.Bool("once", false, "probe once and print results, then exit; ignores the listen flag")
	spread             = flag.Bool("spread", true, "whether to spread probing over time")
	interval           = flag.Duration("interval", 15*time.Second, "probe interval")
	meshInterval       = flag.Duration("mesh-interval", 15*time.Second, "mesh probe interval")
	stunInterval       = flag.Duration("stun-interval", 15*time.Second, "STUN probe interval")
	tlsInterval        = flag.Duration("tls-interval", 15*time.Second, "TLS probe interval")
	bwInterval         = flag.Duration("bw-interval", 0, "bandwidth probe interval (0 = no bandwidth probing)")
	bwSize             = flag.Int64("bw-probe-size-bytes", 1_000_000, "bandwidth probe size")
	bwTUNIPv4Address   = flag.String("bw-tun-ipv4-addr", "", "if specified, bandwidth probes will be performed over a TUN device at this address in order to exercise TCP-in-TCP in similar fashion to TCP over Tailscale via DERP; we will use a /30 subnet including this IP address")
	qdPacketsPerSecond = flag.Int("qd-packets-per-second", 0, "if greater than 0, queuing delay will be measured continuously using 260 byte packets (approximate size of a CallMeMaybe packet) sent at this rate per second")
	qdPacketTimeout    = flag.Duration("qd-packet-timeout", 5*time.Second, "queuing delay packets arriving after this period of time from being sent are treated like dropped packets and don't count toward queuing delay timings")
	regionCodeOrID     = flag.String("region-code", "", "probe only this region (e.g. 'lax' or '17'); if left blank, all regions will be probed")
)

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Long())
		return
	}

	p := prober.New().WithSpread(*spread).WithOnce(*probeOnce).WithMetricNamespace("derpprobe")
	opts := []prober.DERPOpt{
		prober.WithMeshProbing(*meshInterval),
		prober.WithSTUNProbing(*stunInterval),
		prober.WithTLSProbing(*tlsInterval),
		prober.WithQueuingDelayProbing(*qdPacketsPerSecond, *qdPacketTimeout),
	}
	if *bwInterval > 0 {
		opts = append(opts, prober.WithBandwidthProbing(*bwInterval, *bwSize, *bwTUNIPv4Address))
	}
	if *regionCodeOrID != "" {
		opts = append(opts, prober.WithRegionCodeOrID(*regionCodeOrID))
	}
	dp, err := prober.DERP(p, *derpMapURL, opts...)
	if err != nil {
		log.Fatal(err)
	}
	p.Run("derpmap-probe", *interval, nil, dp.ProbeMap)

	if *probeOnce {
		log.Printf("Waiting for all probes (may take up to 1m)")
		p.Wait()

		st := getOverallStatus(p)
		for _, s := range st.good {
			log.Printf("good: %s", s)
		}
		for _, s := range st.bad {
			log.Printf("bad: %s", s)
		}
		return
	}

	mux := http.NewServeMux()
	d := tsweb.Debugger(mux)
	d.Handle("probe-run", "Run a probe", tsweb.StdHandler(tsweb.ReturnHandlerFunc(p.RunHandler), tsweb.HandlerOptions{Logf: log.Printf}))
	mux.Handle("/", tsweb.StdHandler(p.StatusHandler(
		prober.WithTitle("DERP Prober"),
		prober.WithPageLink("Prober metrics", "/debug/varz"),
		prober.WithProbeLink("Run Probe", "/debug/probe-run?name={{.Name}}"),
	), tsweb.HandlerOptions{Logf: log.Printf}))
	mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	}))
	log.Printf("Listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

type overallStatus struct {
	good, bad []string
}

func (st *overallStatus) addBadf(format string, a ...any) {
	st.bad = append(st.bad, fmt.Sprintf(format, a...))
}

func (st *overallStatus) addGoodf(format string, a ...any) {
	st.good = append(st.good, fmt.Sprintf(format, a...))
}

func getOverallStatus(p *prober.Prober) (o overallStatus) {
	for p, i := range p.ProbeInfo() {
		if i.End.IsZero() {
			// Do not show probes that have not finished yet.
			continue
		}
		if i.Status == prober.ProbeStatusSucceeded {
			o.addGoodf("%s: %s", p, i.Latency)
		} else {
			o.addBadf("%s: %s", p, i.Error)
		}
	}

	sort.Strings(o.bad)
	sort.Strings(o.good)
	return
}
