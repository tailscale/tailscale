// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The derpprobe binary probes derpers.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/tailscale/setec/client/setec"
	"tailscale.com/prober"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/version"

	// Support for prometheus varz in tsweb
	_ "tailscale.com/tsweb/promvarz"
)

const meshKeyEnvVar = "TAILSCALE_DERPER_MESH_KEY"
const setecMeshKeyName = "meshkey"

func defaultSetecCacheDir() string {
	return filepath.Join(os.Getenv("HOME"), ".cache", "derper-secrets")
}

var (
	dev                = flag.Bool("dev", false, "run in localhost development mode")
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
	meshPSKFile        = flag.String("mesh-psk-file", "", "if non-empty, path to file containing the mesh pre-shared key file. It must be 64 lowercase hexadecimal characters; whitespace is trimmed.")
	secretsURL         = flag.String("secrets-url", "", "SETEC server URL for secrets retrieval of mesh key")
	secretPrefix       = flag.String("secrets-path-prefix", "prod/derp", fmt.Sprintf("setec path prefix for \"%s\" secret for DERP mesh key", setecMeshKeyName))
	secretsCacheDir    = flag.String("secrets-cache-dir", defaultSetecCacheDir(), "directory to cache setec secrets in (required if --secrets-url is set)")
)

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Long())
		return
	}

	p := prober.New().WithSpread(*spread).WithOnce(*probeOnce).WithMetricNamespace("derpprobe")
	meshKey, err := getMeshKey()
	if err != nil {
		log.Fatalf("failed to get mesh key: %v", err)
	}
	opts := []prober.DERPOpt{
		prober.WithMeshProbing(*meshInterval),
		prober.WithSTUNProbing(*stunInterval),
		prober.WithTLSProbing(*tlsInterval),
		prober.WithQueuingDelayProbing(*qdPacketsPerSecond, *qdPacketTimeout),
		prober.WithMeshKey(meshKey),
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
		if len(st.bad) > 0 {
			os.Exit(1)
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

func getMeshKey() (key.DERPMesh, error) {
	var meshKey string

	if *dev {
		meshKey = os.Getenv(meshKeyEnvVar)
		if meshKey == "" {
			log.Printf("No mesh key specified for dev via %s\n", meshKeyEnvVar)
		} else {
			log.Printf("Set mesh key from %s\n", meshKeyEnvVar)
		}
	} else if *secretsURL != "" {
		meshKeySecret := path.Join(*secretPrefix, setecMeshKeyName)
		fc, err := setec.NewFileCache(*secretsCacheDir)
		if err != nil {
			log.Fatalf("NewFileCache: %v", err)
		}
		log.Printf("Setting up setec store from %q", *secretsURL)
		st, err := setec.NewStore(context.Background(),
			setec.StoreConfig{
				Client: setec.Client{Server: *secretsURL},
				Secrets: []string{
					meshKeySecret,
				},
				Cache: fc,
			})
		if err != nil {
			log.Fatalf("NewStore: %v", err)
		}
		meshKey = st.Secret(meshKeySecret).GetString()
		log.Println("Got mesh key from setec store")
		st.Close()
	} else if *meshPSKFile != "" {
		b, err := setec.StaticFile(*meshPSKFile)
		if err != nil {
			log.Fatalf("StaticFile failed to get key: %v", err)
		}
		log.Println("Got mesh key from static file")
		meshKey = b.GetString()
	}
	if meshKey == "" {
		log.Printf("No mesh key found, mesh key is empty")
		return key.DERPMesh{}, nil
	}

	return key.ParseDERPMesh(meshKey)
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
