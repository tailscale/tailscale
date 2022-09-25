// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.19
// +build go1.19

// The tailscaled program is the Tailscale client daemon. It's configured
// and controlled via the tailscale CLI program.
//
// It primarily supports Linux, though other systems will likely be
// supported in the future.
package main // import "tailscale.com/cmd/tailscaled"

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tailscale.com/cmd/tailscaled/childproc"
	"tailscale.com/control/controlclient"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/dns"
	"tailscale.com/net/netns"
	"tailscale.com/net/proxymux"
	"tailscale.com/net/socks5"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/tsweb"
	"tailscale.com/types/flagtype"
	"tailscale.com/types/logger"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/multierr"
	"tailscale.com/util/osshare"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/monitor"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
)

// defaultTunName returns the default tun device name for the platform.
func defaultTunName() string {
	switch runtime.GOOS {
	case "openbsd":
		return "tun"
	case "windows":
		return "Tailscale"
	case "darwin":
		// "utun" is recognized by wireguard-go/tun/tun_darwin.go
		// as a magic value that uses/creates any free number.
		return "utun"
	case "linux":
		switch distro.Get() {
		case distro.Synology:
			// Try TUN, but fall back to userspace networking if needed.
			// See https://github.com/tailscale/tailscale-synology/issues/35
			return "tailscale0,userspace-networking"
		case distro.Gokrazy:
			// Gokrazy doesn't yet work in tun mode because the whole
			// Gokrazy thing is no C code, and Tailscale currently
			// depends on the iptables binary for Linux's
			// wgengine/router.
			// But on Gokrazy there's no legacy iptables, so we could use netlink
			// to program nft-iptables directly. It just isn't done yet;
			// see https://github.com/tailscale/tailscale/issues/391
			//
			// But Gokrazy does have the tun module built-in, so users
			// can stil run --tun=tailscale0 if they wish, if they
			// arrange for iptables to be present or run in "tailscale
			// up --netfilter-mode=off" mode, perhaps. Untested.
			return "userspace-networking"
		}

	}
	return "tailscale0"
}

// defaultPort returns the default UDP port to listen on for disco+wireguard.
// By default it returns 0, to pick one randomly from the kernel.
// If the environment variable PORT is set, that's used instead.
// The PORT environment variable is chosen to match what the Linux systemd
// unit uses, to make documentation more consistent.
func defaultPort() uint16 {
	if s := envknob.String("PORT"); s != "" {
		if p, err := strconv.ParseUint(s, 10, 16); err == nil {
			return uint16(p)
		}
	}
	return 0
}

var args struct {
	// tunname is a /dev/net/tun tunnel name ("tailscale0"), the
	// string "userspace-networking", "tap:TAPNAME[:BRIDGENAME]"
	// or comma-separated list thereof.
	tunname string

	cleanup        bool
	debug          string
	port           uint16
	statepath      string
	statedir       string
	socketpath     string
	birdSocketPath string
	verbose        int
	socksAddr      string // listen address for SOCKS5 server
	httpProxyAddr  string // listen address for HTTP proxy server
	disableLogs    bool
}

var (
	installSystemDaemon   func([]string) error                      // non-nil on some platforms
	uninstallSystemDaemon func([]string) error                      // non-nil on some platforms
	createBIRDClient      func(string) (wgengine.BIRDClient, error) // non-nil on some platforms
)

var subCommands = map[string]*func([]string) error{
	"install-system-daemon":   &installSystemDaemon,
	"uninstall-system-daemon": &uninstallSystemDaemon,
	"debug":                   &debugModeFunc,
	"be-child":                &beChildFunc,
}

var beCLI func() // non-nil if CLI is linked in

func main() {
	envknob.PanicIfAnyEnvCheckedInInit()
	envknob.ApplyDiskConfig()

	printVersion := false
	flag.IntVar(&args.verbose, "verbose", 0, "log verbosity level; 0 is default, 1 or higher are increasingly verbose")
	flag.BoolVar(&args.cleanup, "cleanup", false, "clean up system state and exit")
	flag.StringVar(&args.debug, "debug", "", "listen address ([ip]:port) of optional debug server")
	flag.StringVar(&args.socksAddr, "socks5-server", "", `optional [ip]:port to run a SOCK5 server (e.g. "localhost:1080")`)
	flag.StringVar(&args.httpProxyAddr, "outbound-http-proxy-listen", "", `optional [ip]:port to run an outbound HTTP proxy (e.g. "localhost:8080")`)
	flag.StringVar(&args.tunname, "tun", defaultTunName(), `tunnel interface name; use "userspace-networking" (beta) to not use TUN`)
	flag.Var(flagtype.PortValue(&args.port, defaultPort()), "port", "UDP port to listen on for WireGuard and peer-to-peer traffic; 0 means automatically select")
	flag.StringVar(&args.statepath, "state", "", "absolute path of state file; use 'kube:<secret-name>' to use Kubernetes secrets or 'arn:aws:ssm:...' to store in AWS SSM; use 'mem:' to not store state and register as an ephemeral node. If empty and --statedir is provided, the default is <statedir>/tailscaled.state. Default: "+paths.DefaultTailscaledStateFile())
	flag.StringVar(&args.statedir, "statedir", "", "path to directory for storage of config state, TLS certs, temporary incoming Taildrop files, etc. If empty, it's derived from --state when possible.")
	flag.StringVar(&args.socketpath, "socket", paths.DefaultTailscaledSocket(), "path of the service unix socket")
	flag.StringVar(&args.birdSocketPath, "bird-socket", "", "path of the bird unix socket")
	flag.BoolVar(&printVersion, "version", false, "print version information and exit")
	flag.BoolVar(&args.disableLogs, "no-logs-no-support", false, "disable log uploads; this also disables any technical support")

	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "tailscale" && beCLI != nil {
		beCLI()
		return
	}

	if len(os.Args) > 1 {
		sub := os.Args[1]
		if fp, ok := subCommands[sub]; ok {
			if *fp == nil {
				log.SetFlags(0)
				log.Fatalf("%s not available on %v", sub, runtime.GOOS)
			}
			if err := (*fp)(os.Args[2:]); err != nil {
				log.SetFlags(0)
				log.Fatal(err)
			}
			return
		}
	}

	flag.Parse()
	if flag.NArg() > 0 {
		// Windows subprocess is spawned with /subprocess, so we need to avoid this check there.
		if runtime.GOOS != "windows" || (flag.Arg(0) != "/subproc" && flag.Arg(0) != "/firewall") {
			log.Fatalf("tailscaled does not take non-flag arguments: %q", flag.Args())
		}
	}

	if printVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	if runtime.GOOS == "darwin" && os.Getuid() != 0 && !strings.Contains(args.tunname, "userspace-networking") && !args.cleanup {
		log.SetFlags(0)
		log.Fatalf("tailscaled requires root; use sudo tailscaled (or use --tun=userspace-networking)")
	}

	if args.socketpath == "" && runtime.GOOS != "windows" {
		log.SetFlags(0)
		log.Fatalf("--socket is required")
	}

	if args.birdSocketPath != "" && createBIRDClient == nil {
		log.SetFlags(0)
		log.Fatalf("--bird-socket is not supported on %s", runtime.GOOS)
	}

	// Only apply a default statepath when neither have been provided, so that a
	// user may specify only --statedir if they wish.
	if args.statepath == "" && args.statedir == "" {
		args.statepath = paths.DefaultTailscaledStateFile()
	}

	if args.disableLogs {
		envknob.SetNoLogsNoSupport()
	}

	if beWindowsSubprocess() {
		return
	}

	err := run()

	// Remove file sharing from Windows shell (noop in non-windows)
	osshare.SetFileSharingEnabled(false, logger.Discard)

	if err != nil {
		log.Fatal(err)
	}
}

func trySynologyMigration(p string) error {
	if runtime.GOOS != "linux" || distro.Get() != distro.Synology {
		return nil
	}

	fi, err := os.Stat(p)
	if err == nil && fi.Size() > 0 || !os.IsNotExist(err) {
		return err
	}
	// File is empty or doesn't exist, try reading from the old path.

	const oldPath = "/var/packages/Tailscale/etc/tailscaled.state"
	if _, err := os.Stat(oldPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	if err := os.Chown(oldPath, os.Getuid(), os.Getgid()); err != nil {
		return err
	}
	if err := os.Rename(oldPath, p); err != nil {
		return err
	}
	return nil
}

func statePathOrDefault() string {
	if args.statepath != "" {
		return args.statepath
	}
	if args.statedir != "" {
		return filepath.Join(args.statedir, "tailscaled.state")
	}
	return ""
}

func ipnServerOpts() (o ipnserver.Options) {
	// Allow changing the OS-specific IPN behavior for tests
	// so we can e.g. test Windows-specific behaviors on Linux.
	goos := envknob.String("TS_DEBUG_TAILSCALED_IPN_GOOS")
	if goos == "" {
		goos = runtime.GOOS
	}

	o.VarRoot = args.statedir

	// If an absolute --state is provided but not --statedir, try to derive
	// a state directory.
	if o.VarRoot == "" && filepath.IsAbs(args.statepath) {
		if dir := filepath.Dir(args.statepath); strings.EqualFold(filepath.Base(dir), "tailscale") {
			o.VarRoot = dir
		}
	}
	if strings.HasPrefix(statePathOrDefault(), "mem:") {
		// Register as an ephemeral node.
		o.LoginFlags = controlclient.LoginEphemeral
	}

	switch goos {
	case "js":
		// The js/wasm client has no state storage so for now
		// treat all interactive logins as ephemeral.
		// TODO(bradfitz): if we start using browser LocalStorage
		// or something, then rethink this.
		o.LoginFlags = controlclient.LoginEphemeral
		fallthrough
	default:
		o.SurviveDisconnects = true
		o.AutostartStateKey = ipn.GlobalDaemonStateKey
	case "windows":
		// Not those.
	}
	return o
}

func run() error {
	var err error

	pol := logpolicy.New(logtail.CollectionNode)
	pol.SetVerbosityLevel(args.verbose)
	defer func() {
		// Finish uploading logs after closing everything else.
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		pol.Shutdown(ctx)
	}()

	if err := envknob.ApplyDiskConfigError(); err != nil {
		log.Printf("Error reading environment config: %v", err)
	}

	if isWindowsService() {
		// Run the IPN server from the Windows service manager.
		log.Printf("Running service...")
		if err := runWindowsService(pol); err != nil {
			log.Printf("runservice: %v", err)
		}
		log.Printf("Service ended.")
		return nil
	}

	var logf logger.Logf = log.Printf
	if envknob.Bool("TS_DEBUG_MEMORY") {
		logf = logger.RusagePrefixLog(logf)
	}
	logf = logger.RateLimitedFn(logf, 5*time.Second, 5, 100)

	if args.cleanup {
		if envknob.Bool("TS_PLEASE_PANIC") {
			panic("TS_PLEASE_PANIC asked us to panic")
		}
		dns.Cleanup(logf, args.tunname)
		router.Cleanup(logf, args.tunname)
		return nil
	}

	if args.statepath == "" && args.statedir == "" {
		log.Fatalf("--statedir (or at least --state) is required")
	}
	if err := trySynologyMigration(statePathOrDefault()); err != nil {
		log.Printf("error in synology migration: %v", err)
	}

	var debugMux *http.ServeMux
	if args.debug != "" {
		debugMux = newDebugMux()
	}

	linkMon, err := monitor.New(logf)
	if err != nil {
		return fmt.Errorf("monitor.New: %w", err)
	}
	pol.Logtail.SetLinkMonitor(linkMon)

	socksListener, httpProxyListener := mustStartProxyListeners(args.socksAddr, args.httpProxyAddr)

	dialer := new(tsdial.Dialer) // mutated below (before used)
	dialer.Logf = logf
	e, useNetstack, err := createEngine(logf, linkMon, dialer)
	if err != nil {
		return fmt.Errorf("createEngine: %w", err)
	}
	if _, ok := e.(wgengine.ResolvingEngine).GetResolver(); !ok {
		panic("internal error: exit node resolver not wired up")
	}
	if debugMux != nil {
		if ig, ok := e.(wgengine.InternalsGetter); ok {
			if _, mc, _, ok := ig.GetInternals(); ok {
				debugMux.HandleFunc("/debug/magicsock", mc.ServeHTTPDebug)
			}
		}
		go runDebugServer(debugMux, args.debug)
	}

	ns, err := newNetstack(logf, dialer, e)
	if err != nil {
		return fmt.Errorf("newNetstack: %w", err)
	}
	ns.ProcessLocalIPs = useNetstack
	ns.ProcessSubnets = useNetstack || shouldWrapNetstack()

	if useNetstack {
		dialer.UseNetstackForIP = func(ip netip.Addr) bool {
			_, ok := e.PeerForIP(ip)
			return ok
		}
		dialer.NetstackDialTCP = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return ns.DialContextTCP(ctx, dst)
		}
	}
	if socksListener != nil || httpProxyListener != nil {
		if httpProxyListener != nil {
			hs := &http.Server{Handler: httpProxyHandler(dialer.UserDial)}
			go func() {
				log.Fatalf("HTTP proxy exited: %v", hs.Serve(httpProxyListener))
			}()
		}
		if socksListener != nil {
			ss := &socks5.Server{
				Logf:   logger.WithPrefix(logf, "socks5: "),
				Dialer: dialer.UserDial,
			}
			go func() {
				log.Fatalf("SOCKS5 server exited: %v", ss.Serve(socksListener))
			}()
		}
	}

	e = wgengine.NewWatchdog(e)

	ctx, cancel := context.WithCancel(context.Background())
	// Exit gracefully by cancelling the ipnserver context in most common cases:
	// interrupted from the TTY or killed by a service manager.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	// SIGPIPE sometimes gets generated when CLIs disconnect from
	// tailscaled. The default action is to terminate the process, we
	// want to keep running.
	signal.Ignore(syscall.SIGPIPE)
	go func() {
		select {
		case s := <-interrupt:
			logf("tailscaled got signal %v; shutting down", s)
			cancel()
		case <-ctx.Done():
			// continue
		}
	}()

	opts := ipnServerOpts()

	store, err := store.New(logf, statePathOrDefault())
	if err != nil {
		return fmt.Errorf("store.New: %w", err)
	}
	srv, err := ipnserver.New(logf, pol.PublicID.String(), store, e, dialer, nil, opts)
	if err != nil {
		return fmt.Errorf("ipnserver.New: %w", err)
	}
	ns.SetLocalBackend(srv.LocalBackend())
	if err := ns.Start(); err != nil {
		log.Fatalf("failed to start netstack: %v", err)
	}

	if debugMux != nil {
		debugMux.HandleFunc("/debug/ipn", srv.ServeHTMLStatus)
	}

	ln, _, err := safesocket.Listen(args.socketpath, safesocket.WindowsLocalPort)
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}
	defer dialer.Close()

	err = srv.Run(ctx, ln)
	// Cancelation is not an error: it is the only way to stop ipnserver.
	if err != nil && err != context.Canceled {
		return fmt.Errorf("ipnserver.Run: %w", err)
	}

	return nil
}

func createEngine(logf logger.Logf, linkMon *monitor.Mon, dialer *tsdial.Dialer) (e wgengine.Engine, useNetstack bool, err error) {
	if args.tunname == "" {
		return nil, false, errors.New("no --tun value specified")
	}
	var errs []error
	for _, name := range strings.Split(args.tunname, ",") {
		logf("wgengine.NewUserspaceEngine(tun %q) ...", name)
		e, useNetstack, err = tryEngine(logf, linkMon, dialer, name)
		if err == nil {
			return e, useNetstack, nil
		}
		logf("wgengine.NewUserspaceEngine(tun %q) error: %v", name, err)
		errs = append(errs, err)
	}
	return nil, false, multierr.New(errs...)
}

func shouldWrapNetstack() bool {
	if v, ok := envknob.LookupBool("TS_DEBUG_WRAP_NETSTACK"); ok {
		return v
	}
	if distro.Get() == distro.Synology {
		return true
	}
	switch runtime.GOOS {
	case "windows", "darwin", "freebsd", "openbsd":
		// Enable on Windows and tailscaled-on-macOS (this doesn't
		// affect the GUI clients), and on FreeBSD.
		return true
	}
	return false
}

func tryEngine(logf logger.Logf, linkMon *monitor.Mon, dialer *tsdial.Dialer, name string) (e wgengine.Engine, useNetstack bool, err error) {
	conf := wgengine.Config{
		ListenPort:  args.port,
		LinkMonitor: linkMon,
		Dialer:      dialer,
	}

	useNetstack = name == "userspace-networking"
	netns.SetEnabled(!useNetstack)

	if args.birdSocketPath != "" && createBIRDClient != nil {
		log.Printf("Connecting to BIRD at %s ...", args.birdSocketPath)
		conf.BIRDClient, err = createBIRDClient(args.birdSocketPath)
		if err != nil {
			return nil, false, fmt.Errorf("createBIRDClient: %w", err)
		}
	}
	if useNetstack {
		if runtime.GOOS == "linux" && distro.Get() == distro.Synology {
			// On Synology in netstack mode, still init a DNS
			// manager (directManager) to avoid the health check
			// warnings in 'tailscale status' about DNS base
			// configuration being unavailable (from the noop
			// manager). More in Issue 4017.
			// TODO(bradfitz): add a Synology-specific DNS manager.
			conf.DNS, err = dns.NewOSConfigurator(logf, "") // empty interface name
			if err != nil {
				return nil, false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
			}
		}
	} else {
		dev, devName, err := tstun.New(logf, name)
		if err != nil {
			tstun.Diagnose(logf, name, err)
			return nil, false, fmt.Errorf("tstun.New(%q): %w", name, err)
		}
		conf.Tun = dev
		if strings.HasPrefix(name, "tap:") {
			conf.IsTAP = true
			e, err := wgengine.NewUserspaceEngine(logf, conf)
			return e, false, err
		}

		r, err := router.New(logf, dev, linkMon)
		if err != nil {
			dev.Close()
			return nil, false, fmt.Errorf("creating router: %w", err)
		}
		d, err := dns.NewOSConfigurator(logf, devName)
		if err != nil {
			return nil, false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
		}
		conf.DNS = d
		conf.Router = r
		if shouldWrapNetstack() {
			conf.Router = netstack.NewSubnetRouterWrapper(conf.Router)
		}
	}
	e, err = wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		return nil, useNetstack, err
	}
	return e, useNetstack, nil
}

func newDebugMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/metrics", servePrometheusMetrics)
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

func servePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	tsweb.VarzHandler(w, r)
	clientmetric.WritePrometheusExpositionFormat(w)
}

func runDebugServer(mux *http.ServeMux, addr string) {
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func newNetstack(logf logger.Logf, dialer *tsdial.Dialer, e wgengine.Engine) (*netstack.Impl, error) {
	tunDev, magicConn, dns, ok := e.(wgengine.InternalsGetter).GetInternals()
	if !ok {
		return nil, fmt.Errorf("%T is not a wgengine.InternalsGetter", e)
	}
	return netstack.Create(logf, tunDev, e, magicConn, dialer, dns)
}

// mustStartProxyListeners creates listeners for local SOCKS and HTTP
// proxies, if the respective addresses are not empty. socksAddr and
// httpAddr can be the same, in which case socksListener will receive
// connections that look like they're speaking SOCKS and httpListener
// will receive everything else.
//
// socksListener and httpListener can be nil, if their respective
// addrs are empty.
func mustStartProxyListeners(socksAddr, httpAddr string) (socksListener, httpListener net.Listener) {
	if socksAddr == httpAddr && socksAddr != "" && !strings.HasSuffix(socksAddr, ":0") {
		ln, err := net.Listen("tcp", socksAddr)
		if err != nil {
			log.Fatalf("proxy listener: %v", err)
		}
		return proxymux.SplitSOCKSAndHTTP(ln)
	}

	var err error
	if socksAddr != "" {
		socksListener, err = net.Listen("tcp", socksAddr)
		if err != nil {
			log.Fatalf("SOCKS5 listener: %v", err)
		}
		if strings.HasSuffix(socksAddr, ":0") {
			// Log kernel-selected port number so integration tests
			// can find it portably.
			log.Printf("SOCKS5 listening on %v", socksListener.Addr())
		}
	}
	if httpAddr != "" {
		httpListener, err = net.Listen("tcp", httpAddr)
		if err != nil {
			log.Fatalf("HTTP proxy listener: %v", err)
		}
		if strings.HasSuffix(httpAddr, ":0") {
			// Log kernel-selected port number so integration tests
			// can find it portably.
			log.Printf("HTTP proxy listening on %v", httpListener.Addr())
		}
	}

	return socksListener, httpListener
}

var beChildFunc = beChild

func beChild(args []string) error {
	if len(args) == 0 {
		return errors.New("missing mode argument")
	}
	typ := args[0]
	f, ok := childproc.Code[typ]
	if !ok {
		return fmt.Errorf("unknown be-child mode %q", typ)
	}
	return f(args[1:])
}
