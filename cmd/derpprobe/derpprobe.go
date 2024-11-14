// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The derpprobe binary probes derpers.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
	"tailscale.com/prober"
	"tailscale.com/tsweb"
	"tailscale.com/version"
)

var (
	derpMapURL   = flag.String("derp-map", "https://login.tailscale.com/derpmap/default", "URL to DERP map (https:// or file://) or 'local' to use the local tailscaled's DERP map")
	versionFlag  = flag.Bool("version", false, "print version and exit")
	listen       = flag.String("listen", ":8030", "HTTP listen address")
	probeOnce    = flag.Bool("once", false, "probe once and print results, then exit; ignores the listen flag")
	spread       = flag.Bool("spread", true, "whether to spread probing over time")
	interval     = flag.Duration("interval", 15*time.Second, "probe interval")
	meshInterval = flag.Duration("mesh-interval", 15*time.Second, "mesh probe interval")
	stunInterval = flag.Duration("stun-interval", 15*time.Second, "STUN probe interval")
	tlsInterval  = flag.Duration("tls-interval", 15*time.Second, "TLS probe interval")
	bwInterval   = flag.Duration("bw-interval", 0, "bandwidth probe interval (0 = no bandwidth probing)")
	bwSize       = flag.Int64("bw-probe-size-bytes", 1_000_000, "bandwidth probe size")
	configFile   = flag.String("config", "", "use this yaml file to configure probes; if specified, overrides all other flags")
)

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Long())
		return
	}

	// Read config from yaml file, or populate from flags.
	// Note that we do not use flag.YYYVar because we don't want to mix flags
	// and config, it's an either/or situation.
	var cfg config
	if *configFile != "" {
		b, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("failed to read config file %q: %s", *configFile, err)
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			log.Fatalf("failed to parse config file %q: %s", *configFile, err)
		}
	} else {
		cfg.DerpMap = *derpMapURL
		cfg.ListenAddr = *listen
		cfg.ProbeOnce = *probeOnce
		cfg.Spread = *spread
		cfg.MapInterval = *interval
		cfg.Mesh.Interval = *meshInterval
		cfg.STUN.Interval = *stunInterval
		cfg.TLS.Interval = *tlsInterval
		cfg.Bandwidth.Interval = *bwInterval
		cfg.Bandwidth.Size = *bwSize
	}

	p := prober.New().WithSpread(cfg.Spread).WithOnce(cfg.ProbeOnce).WithMetricNamespace("derpprobe")
	var opts []prober.DERPOpt
	if cfg.Mesh.Interval > 0 {
		opts = append(opts, prober.WithMeshProbing(cfg.Mesh.Interval))
	}
	if cfg.STUN.Interval > 0 {
		opts = append(opts, prober.WithSTUNProbing(cfg.STUN.Interval))
	}
	if cfg.TLS.Interval > 0 {
		opts = append(opts, prober.WithTLSProbing(cfg.TLS.Interval))
	}
	if cfg.Bandwidth.Interval > 0 {
		opts = append(opts, prober.WithBandwidthProbing(cfg.Bandwidth.Interval, cfg.Bandwidth.Size))
	}
	dp, err := prober.DERP(p, cfg.DerpMap, opts...)
	if err != nil {
		log.Fatal(err)
	}
	p.Run("derpmap-probe", cfg.MapInterval, nil, dp.ProbeMap)

	if cfg.ProbeOnce {
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
	log.Printf("Listening on %s", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
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
