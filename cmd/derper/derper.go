// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The derper binary is a simple DERP server.
//
// For more information, see:
//
//   - About: https://tailscale.com/kb/1232/derp-servers
//   - Protocol & Go docs: https://pkg.go.dev/tailscale.com/derp
//   - Running a DERP server: https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp
package main // import "tailscale.com/cmd/derper"

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	runtimemetrics "runtime/metrics"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tailscale/setec/client/setec"
	"golang.org/x/time/rate"
	"tailscale.com/atomicfile"
	"tailscale.com/derp/derpserver"
	"tailscale.com/metrics"
	"tailscale.com/net/ktimeout"
	"tailscale.com/net/stunserver"
	"tailscale.com/tsweb"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/version"

	// Support for prometheus varz in tsweb
	_ "tailscale.com/tsweb/promvarz"
)

var (
	dev         = flag.Bool("dev", false, "run in localhost development mode (overrides -a)")
	versionFlag = flag.Bool("version", false, "print version and exit")
	addr        = flag.String("a", ":443", "server HTTP/HTTPS listen address, in form \":port\", \"ip:port\", or for IPv6 \"[ip]:port\". If the IP is omitted, it defaults to all interfaces. Serves HTTPS if the port is 443 and/or -certmode is manual, otherwise HTTP.")
	httpPort    = flag.Int("http-port", 80, "The port on which to serve HTTP. Set to -1 to disable. The listener is bound to the same IP (if any) as specified in the -a flag.")
	stunPort    = flag.Int("stun-port", 3478, "The UDP port on which to serve STUN. The listener is bound to the same IP (if any) as specified in the -a flag.")
	configPath  = flag.String("c", "", "config file path")
	certMode    = flag.String("certmode", "letsencrypt", "mode for getting a cert. possible options: manual, letsencrypt")
	certDir     = flag.String("certdir", tsweb.DefaultCertDir("derper-certs"), "directory to store LetsEncrypt certs, if addr's port is :443")
	hostname    = flag.String("hostname", "derp.tailscale.com", "LetsEncrypt host name, if addr's port is :443. When --certmode=manual, this can be an IP address to avoid SNI checks")
	runSTUN     = flag.Bool("stun", true, "whether to run a STUN server. It will bind to the same IP (if any) as the --addr flag value.")
	runDERP     = flag.Bool("derp", true, "whether to run a DERP server. The only reason to set this false is if you're decommissioning a server but want to keep its bootstrap DNS functionality still running.")
	flagHome    = flag.String("home", "", "what to serve at the root path. It may be left empty (the default, for a default homepage), \"blank\" for a blank page, or a URL to redirect to")

	meshPSKFile     = flag.String("mesh-psk-file", defaultMeshPSKFile(), "if non-empty, path to file containing the mesh pre-shared key file. It must be 64 lowercase hexadecimal characters; whitespace is trimmed.")
	meshWith        = flag.String("mesh-with", "", "optional comma-separated list of hostnames to mesh with; the server's own hostname can be in the list. If an entry contains a slash, the second part names a hostname to be used when dialing the target.")
	secretsURL      = flag.String("secrets-url", "", "SETEC server URL for secrets retrieval of mesh key")
	secretPrefix    = flag.String("secrets-path-prefix", "prod/derp", "setec path prefix for \""+setecMeshKeyName+"\" secret for DERP mesh key")
	secretsCacheDir = flag.String("secrets-cache-dir", defaultSetecCacheDir(), "directory to cache setec secrets in (required if --secrets-url is set)")
	bootstrapDNS    = flag.String("bootstrap-dns-names", "", "optional comma-separated list of hostnames to make available at /bootstrap-dns")
	unpublishedDNS  = flag.String("unpublished-bootstrap-dns-names", "", "optional comma-separated list of hostnames to make available at /bootstrap-dns and not publish in the list. If an entry contains a slash, the second part names a DNS record to poll for its TXT record with a `0` to `100` value for rollout percentage.")

	verifyClients   = flag.Bool("verify-clients", false, "verify clients to this DERP server through a local tailscaled instance.")
	verifyClientURL = flag.String("verify-client-url", "", "if non-empty, an admission controller URL for permitting client connections; see tailcfg.DERPAdmitClientRequest")
	verifyFailOpen  = flag.Bool("verify-client-url-fail-open", true, "whether we fail open if --verify-client-url is unreachable")

	socket = flag.String("socket", "", "optional alternate path to tailscaled socket (only relevant when using --verify-clients)")

	acceptConnLimit = flag.Float64("accept-connection-limit", math.Inf(+1), "rate limit for accepting new connection")
	acceptConnBurst = flag.Int("accept-connection-burst", math.MaxInt, "burst limit for accepting new connection")

	// tcpKeepAlive is intentionally long, to reduce battery cost. There is an L7 keepalive on a higher frequency schedule.
	tcpKeepAlive = flag.Duration("tcp-keepalive-time", 10*time.Minute, "TCP keepalive time")
	// tcpUserTimeout is intentionally short, so that hung connections are cleaned up promptly. DERPs should be nearby users.
	tcpUserTimeout = flag.Duration("tcp-user-timeout", 15*time.Second, "TCP user timeout")
	// tcpWriteTimeout is the timeout for writing to client TCP connections. It does not apply to mesh connections.
	tcpWriteTimeout = flag.Duration("tcp-write-timeout", derpserver.DefaultTCPWiteTimeout, "TCP write timeout; 0 results in no timeout being set on writes")

	// ACE
	flagACEEnabled = flag.Bool("ace", false, "whether to enable embedded ACE server [experimental + in-development as of 2025-09-12; not yet documented]")
)

var (
	tlsRequestVersion = &metrics.LabelMap{Label: "version"}
	tlsActiveVersion  = &metrics.LabelMap{Label: "version"}
)

const setecMeshKeyName = "meshkey"
const meshKeyEnvVar = "TAILSCALE_DERPER_MESH_KEY"

func init() {
	expvar.Publish("derper_tls_request_version", tlsRequestVersion)
	expvar.Publish("gauge_derper_tls_active_version", tlsActiveVersion)
}

type config struct {
	PrivateKey key.NodePrivate
}

func loadConfig() config {
	if *dev {
		return config{PrivateKey: key.NewNode()}
	}
	if *configPath == "" {
		if os.Getuid() == 0 {
			*configPath = "/var/lib/derper/derper.key"
		} else {
			log.Fatalf("derper: -c <config path> not specified")
		}
		log.Printf("no config path specified; using %s", *configPath)
	}
	b, err := os.ReadFile(*configPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return writeNewConfig()
	case err != nil:
		log.Fatal(err)
		panic("unreachable")
	default:
		var cfg config
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Fatalf("derper: config: %v", err)
		}
		return cfg
	}
}

func writeNewConfig() config {
	k := key.NewNode()
	if err := os.MkdirAll(filepath.Dir(*configPath), 0777); err != nil {
		log.Fatal(err)
	}
	cfg := config{
		PrivateKey: k,
	}
	b, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	if err := atomicfile.WriteFile(*configPath, b, 0600); err != nil {
		log.Fatal(err)
	}
	return cfg
}

func main() {
	flag.Parse()
	if *versionFlag {
		fmt.Println(version.Long())
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if *dev {
		*addr = ":3340" // above the keys DERP
		log.Printf("Running in dev mode.")
		tsweb.DevMode = true
	}

	listenHost, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatalf("invalid server address: %v", err)
	}

	if *runSTUN {
		ss := stunserver.New(ctx)
		go ss.ListenAndServe(net.JoinHostPort(listenHost, fmt.Sprint(*stunPort)))
	}

	cfg := loadConfig()

	serveTLS := tsweb.IsProd443(*addr) || *certMode == "manual"

	s := derpserver.New(cfg.PrivateKey, log.Printf)
	s.SetVerifyClient(*verifyClients)
	s.SetTailscaledSocketPath(*socket)
	s.SetVerifyClientURL(*verifyClientURL)
	s.SetVerifyClientURLFailOpen(*verifyFailOpen)
	s.SetTCPWriteTimeout(*tcpWriteTimeout)

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
		st, err := setec.NewStore(ctx,
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

	if meshKey == "" && *dev {
		log.Printf("No mesh key configured for --dev mode")
	} else if meshKey == "" {
		log.Printf("No mesh key configured")
	} else if err := s.SetMeshKey(meshKey); err != nil {
		log.Fatalf("invalid mesh key: %v", err)
	} else {
		log.Println("DERP mesh key configured")
	}

	if err := startMesh(s); err != nil {
		log.Fatalf("startMesh: %v", err)
	}
	expvar.Publish("derp", s.ExpVar())

	handleHome, ok := getHomeHandler(*flagHome)
	if !ok {
		log.Fatalf("unknown --home value %q", *flagHome)
	}

	mux := http.NewServeMux()
	if *runDERP {
		derpHandler := derpserver.Handler(s)
		derpHandler = addWebSocketSupport(s, derpHandler)
		mux.Handle("/derp", derpHandler)
	} else {
		mux.Handle("/derp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "derp server disabled", http.StatusNotFound)
		}))
	}

	// These two endpoints are the same. Different versions of the clients
	// have assumes different paths over time so we support both.
	mux.HandleFunc("/derp/probe", derpserver.ProbeHandler)
	mux.HandleFunc("/derp/latency-check", derpserver.ProbeHandler)

	go refreshBootstrapDNSLoop()
	mux.HandleFunc("/bootstrap-dns", tsweb.BrowserHeaderHandlerFunc(handleBootstrapDNS))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tsweb.AddBrowserHeaders(w)
		handleHome.ServeHTTP(w, r)
	}))
	mux.Handle("/robots.txt", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tsweb.AddBrowserHeaders(w)
		io.WriteString(w, "User-agent: *\nDisallow: /\n")
	}))
	mux.Handle("/generate_204", http.HandlerFunc(derpserver.ServeNoContent))
	debug := tsweb.Debugger(mux)
	debug.KV("TLS hostname", *hostname)
	debug.KV("Mesh key", s.HasMeshKey())
	debug.Handle("check", "Consistency check", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := s.ConsistencyCheck()
		if err != nil {
			http.Error(w, err.Error(), 500)
		} else {
			io.WriteString(w, "derp.Server ConsistencyCheck okay")
		}
	}))
	debug.Handle("traffic", "Traffic check", http.HandlerFunc(s.ServeDebugTraffic))
	debug.Handle("set-mutex-profile-fraction", "SetMutexProfileFraction", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := r.FormValue("rate")
		if s == "" || r.Header.Get("Sec-Debug") != "derp" {
			http.Error(w, "To set, use: curl -HSec-Debug:derp 'http://derp/debug/set-mutex-profile-fraction?rate=100'", http.StatusBadRequest)
			return
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			http.Error(w, "bad rate value", http.StatusBadRequest)
			return
		}
		old := runtime.SetMutexProfileFraction(v)
		fmt.Fprintf(w, "mutex changed from %v to %v\n", old, v)
	}))

	// Longer lived DERP connections send an application layer keepalive. Note
	// if the keepalive is hit, the user timeout will take precedence over the
	// keepalive counter, so the probe if unanswered will take effect promptly,
	// this is less tolerant of high loss, but high loss is unexpected.
	lc := net.ListenConfig{
		Control:   ktimeout.UserTimeout(*tcpUserTimeout),
		KeepAlive: *tcpKeepAlive,
	}
	// As of 2025-02-19, MPTCP does not support TCP_USER_TIMEOUT socket option
	// set in ktimeout.UserTimeout above.
	lc.SetMultipathTCP(false)

	quietLogger := log.New(logger.HTTPServerLogFilter{Inner: log.Printf}, "", 0)
	httpsrv := &http.Server{
		Addr:     *addr,
		Handler:  mux,
		ErrorLog: quietLogger,

		// Set read/write timeout. For derper, this basically
		// only affects TLS setup, as read/write deadlines are
		// cleared on Hijack, which the DERP server does. But
		// without this, we slowly accumulate stuck TLS
		// handshake goroutines forever. This also affects
		// /debug/ traffic, but 30 seconds is plenty for
		// Prometheus/etc scraping.
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	go func() {
		<-ctx.Done()
		httpsrv.Shutdown(ctx)
	}()

	if serveTLS {
		log.Printf("derper: serving on %s with TLS", *addr)
		var certManager certProvider
		certManager, err = certProviderByCertMode(*certMode, *certDir, *hostname)
		if err != nil {
			log.Fatalf("derper: can not start cert provider: %v", err)
		}
		httpsrv.TLSConfig = certManager.TLSConfig()
		getCert := httpsrv.TLSConfig.GetCertificate
		httpsrv.TLSConfig.GetCertificate = func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := getCert(hi)
			if err != nil {
				return nil, err
			}
			cert.Certificate = append(cert.Certificate, s.MetaCert())
			return cert, nil
		}
		// Disable TLS 1.0 and 1.1, which are obsolete and have security issues.
		httpsrv.TLSConfig.MinVersion = tls.VersionTLS12
		httpsrv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				label := "unknown"
				switch r.TLS.Version {
				case tls.VersionTLS10:
					label = "1.0"
				case tls.VersionTLS11:
					label = "1.1"
				case tls.VersionTLS12:
					label = "1.2"
				case tls.VersionTLS13:
					label = "1.3"
				}
				tlsRequestVersion.Add(label, 1)
				tlsActiveVersion.Add(label, 1)
				defer tlsActiveVersion.Add(label, -1)

				if r.Method == "CONNECT" {
					serveConnect(s, w, r)
					return
				}
			}

			mux.ServeHTTP(w, r)
		})
		if *httpPort > -1 {
			go func() {
				port80mux := http.NewServeMux()
				port80mux.HandleFunc("/generate_204", derpserver.ServeNoContent)
				port80mux.Handle("/", certManager.HTTPHandler(tsweb.Port80Handler{Main: mux}))
				port80srv := &http.Server{
					Addr:        net.JoinHostPort(listenHost, fmt.Sprintf("%d", *httpPort)),
					Handler:     port80mux,
					ErrorLog:    quietLogger,
					ReadTimeout: 30 * time.Second,
					// Crank up WriteTimeout a bit more than usually
					// necessary just so we can do long CPU profiles
					// and not hit net/http/pprof's "profile
					// duration exceeds server's WriteTimeout".
					WriteTimeout: 5 * time.Minute,
				}
				ln, err := lc.Listen(context.Background(), "tcp", port80srv.Addr)
				if err != nil {
					log.Fatal(err)
				}
				defer ln.Close()
				err = port80srv.Serve(ln)
				if err != nil {
					if err != http.ErrServerClosed {
						log.Fatal(err)
					}
				}
			}()
		}
		err = rateLimitedListenAndServeTLS(httpsrv, &lc)
	} else {
		log.Printf("derper: serving on %s", *addr)
		var ln net.Listener
		ln, err = lc.Listen(context.Background(), "tcp", httpsrv.Addr)
		if err != nil {
			log.Fatal(err)
		}
		err = httpsrv.Serve(ln)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("derper: %v", err)
	}
}

var validProdHostname = regexp.MustCompile(`^derp([^.]*)\.tailscale\.com\.?$`)

func prodAutocertHostPolicy(_ context.Context, host string) error {
	if validProdHostname.MatchString(host) {
		return nil
	}
	return errors.New("invalid hostname")
}

func defaultSetecCacheDir() string {
	return filepath.Join(os.Getenv("HOME"), ".cache", "derper-secrets")
}

func defaultMeshPSKFile() string {
	try := []string{
		"/home/derp/keys/derp-mesh.key",
		filepath.Join(os.Getenv("HOME"), "keys", "derp-mesh.key"),
	}
	for _, p := range try {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func rateLimitedListenAndServeTLS(srv *http.Server, lc *net.ListenConfig) error {
	ln, err := lc.Listen(context.Background(), "tcp", cmp.Or(srv.Addr, ":https"))
	if err != nil {
		return err
	}
	rln := newRateLimitedListener(ln, rate.Limit(*acceptConnLimit), *acceptConnBurst)
	expvar.Publish("tls_listener", rln.ExpVar())
	defer rln.Close()
	return srv.ServeTLS(rln, "", "")
}

type rateLimitedListener struct {
	// These are at the start of the struct to ensure 64-bit alignment
	// on 32-bit architecture regardless of what other fields may exist
	// in this package.
	numAccepts expvar.Int // does not include number of rejects
	numRejects expvar.Int

	net.Listener

	lim *rate.Limiter
}

func newRateLimitedListener(ln net.Listener, limit rate.Limit, burst int) *rateLimitedListener {
	return &rateLimitedListener{Listener: ln, lim: rate.NewLimiter(limit, burst)}
}

func (l *rateLimitedListener) ExpVar() expvar.Var {
	m := new(metrics.Set)
	m.Set("counter_accepted_connections", &l.numAccepts)
	m.Set("counter_rejected_connections", &l.numRejects)
	return m
}

var errLimitedConn = errors.New("cannot accept connection; rate limited")

func (l *rateLimitedListener) Accept() (net.Conn, error) {
	// Even under a rate limited situation, we accept the connection immediately
	// and close it, rather than being slow at accepting new connections.
	// This provides two benefits: 1) it signals to the client that something
	// is going on on the server, and 2) it prevents new connections from
	// piling up and occupying resources in the OS kernel.
	// The client will retry as needing (with backoffs in place).
	cn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !l.lim.Allow() {
		l.numRejects.Add(1)
		cn.Close()
		return nil, errLimitedConn
	}
	l.numAccepts.Add(1)
	return cn, nil
}

func init() {
	expvar.Publish("go_sync_mutex_wait_seconds", expvar.Func(func() any {
		const name = "/sync/mutex/wait/total:seconds" // Go 1.20+
		var s [1]runtimemetrics.Sample
		s[0].Name = name
		runtimemetrics.Read(s[:])
		if v := s[0].Value; v.Kind() == runtimemetrics.KindFloat64 {
			return v.Float64()
		}
		return 0
	}))
}

type templateData struct {
	ShowAbuseInfo bool
	Disabled      bool
	AllowDebug    bool
}

// homePageTemplate renders the home page using [templateData].
var homePageTemplate = template.Must(template.New("home").Parse(`<html><body>
<h1>DERP</h1>
<p>
  This is a <a href="https://tailscale.com/">Tailscale</a> DERP server.
</p>

<p>
  It provides STUN, interactive connectivity establishment, and relaying of end-to-end encrypted traffic
  for Tailscale clients.
</p>

{{if .ShowAbuseInfo }}
<p>
  If you suspect abuse, please contact <a href="mailto:security@tailscale.com">security@tailscale.com</a>.
</p>
{{end}}

<p>
  Documentation:
</p>

<ul>
{{if .ShowAbuseInfo }}
  <li><a href="https://tailscale.com/security-policies">Tailscale Security Policies</a></li>
  <li><a href="https://tailscale.com/tailscale-aup">Tailscale Acceptable Use Policies</a></li>
{{end}}
  <li><a href="https://tailscale.com/kb/1232/derp-servers">About DERP</a></li>
  <li><a href="https://pkg.go.dev/tailscale.com/derp">Protocol & Go docs</a></li>
  <li><a href="https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp">How to run a DERP server</a></li>
</ul>

{{if .Disabled}}
<p>Status: <b>disabled</b></p>
{{end}}

{{if .AllowDebug}}
<p>Debug info at <a href='/debug/'>/debug/</a>.</p>
{{end}}
</body>
</html>
`))

// getHomeHandler returns a handler for the home page based on a flag string
// as documented on the --home flag.
func getHomeHandler(val string) (_ http.Handler, ok bool) {
	if val == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
			err := homePageTemplate.Execute(w, templateData{
				ShowAbuseInfo: validProdHostname.MatchString(*hostname),
				Disabled:      !*runDERP,
				AllowDebug:    tsweb.AllowDebugAccess(r),
			})
			if err != nil {
				if r.Context().Err() == nil {
					log.Printf("homePageTemplate.Execute: %v", err)
				}
				return
			}
		}), true
	}
	if val == "blank" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(200)
		}), true
	}
	if strings.HasPrefix(val, "http://") || strings.HasPrefix(val, "https://") {
		return http.RedirectHandler(val, http.StatusFound), true
	}
	return nil, false
}
