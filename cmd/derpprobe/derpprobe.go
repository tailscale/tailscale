// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The derpprobe binary probes derpers.
package main

import (
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"sort"
	"time"

	"tailscale.com/prober"
	"tailscale.com/tsweb"
)

var (
	derpMapURL   = flag.String("derp-map", "https://login.tailscale.com/derpmap/default", "URL to DERP map (https:// or file://)")
	listen       = flag.String("listen", ":8030", "HTTP listen address")
	probeOnce    = flag.Bool("once", false, "probe once and print results, then exit; ignores the listen flag")
	spread       = flag.Bool("spread", true, "whether to spread probing over time")
	interval     = flag.Duration("interval", 15*time.Second, "probe interval")
	meshInterval = flag.Duration("mesh-interval", 15*time.Second, "mesh probe interval")
	stunInterval = flag.Duration("stun-interval", 15*time.Second, "STUN probe interval")
	tlsInterval  = flag.Duration("tls-interval", 15*time.Second, "TLS probe interval")
	bwInterval   = flag.Duration("bw-interval", 0, "bandwidth probe interval (0 = no bandwidth probing)")
	bwSize       = flag.Int64("bw-probe-size-bytes", 1_000_000, "bandwidth probe size")
)

func main() {
	flag.Parse()

	p := prober.New().WithSpread(*spread).WithOnce(*probeOnce).WithMetricNamespace("derpprobe")
	opts := []prober.DERPOpt{
		prober.WithMeshProbing(*meshInterval),
		prober.WithSTUNProbing(*stunInterval),
		prober.WithTLSProbing(*tlsInterval),
	}
	if *bwInterval > 0 {
		opts = append(opts, prober.WithBandwidthProbing(*bwInterval, *bwSize))
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
	tsweb.Debugger(mux)
	mux.HandleFunc("/", http.HandlerFunc(serveFunc(p)))
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
		if i.Result {
			o.addGoodf("%s: %s", p, i.Latency)
		} else {
			o.addBadf("%s: %s", p, i.Error)
		}
	}

	sort.Strings(o.bad)
	sort.Strings(o.good)
	return
}

func serveFunc(p *prober.Prober) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		st := getOverallStatus(p)
		summary := "All good"
		if (float64(len(st.bad)) / float64(len(st.bad)+len(st.good))) > 0.25 {
			// Returning a 500 allows monitoring this server externally and configuring
			// an alert on HTTP response code.
			w.WriteHeader(500)
			summary = fmt.Sprintf("%d problems", len(st.bad))
		}

		io.WriteString(w, "<html><head><style>.bad { font-weight: bold; color: #700; }</style></head>\n")
		fmt.Fprintf(w, "<body><h1>derp probe</h1>\n%s:<ul>", summary)
		for _, s := range st.bad {
			fmt.Fprintf(w, "<li class=bad>%s</li>\n", html.EscapeString(s))
		}
		for _, s := range st.good {
			fmt.Fprintf(w, "<li>%s</li>\n", html.EscapeString(s))
		}
		io.WriteString(w, "</ul></body></html>\n")
	}
}
