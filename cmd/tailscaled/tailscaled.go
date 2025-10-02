// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.23

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
	"tailscale.com/feature"
	"tailscale.com/feature/buildfeatures"
	_ "tailscale.com/feature/condregister"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/conffile"
	"tailscale.com/ipn/ipnlocal"
	"tailscale.com/ipn/ipnserver"
	"tailscale.com/ipn/store"
	"tailscale.com/logpolicy"
	"tailscale.com/logtail"
	"tailscale.com/net/dns"
	"tailscale.com/net/dnsfallback"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/paths"
	"tailscale.com/safesocket"
	"tailscale.com/syncs"
	"tailscale.com/tsd"
	"tailscale.com/tsweb/varz"
	"tailscale.com/types/flagtype"
	"tailscale.com/types/logger"
	"tailscale.com/types/logid"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/osshare"
	"tailscale.com/util/syspolicy/pkey"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/version"
	"tailscale.com/version/distro"
	"tailscale.com/wgengine"
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
	case "plan9":
		return "auto"
	case "aix", "solaris", "illumos":
		return "userspace-networking"
	case "linux":
		switch distro.Get() {
		case distro.Synology:
			// Try TUN, but fall back to userspace networking if needed.
			// See https://github.com/tailscale/tailscale-synology/issues/35
			return "tailscale0,userspace-networking"
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
	if envknob.GOOS() == "windows" {
		return 41641
	}
	return 0
}

var args struct {
	// tunname is a /dev/net/tun tunnel name ("tailscale0"), the
	// string "userspace-networking", "tap:TAPNAME[:BRIDGENAME]"
	// or comma-separated list thereof.
	tunname string

	cleanUp        bool
	confFile       string // empty, file path, or "vm:user-data"
	debug          string
	port           uint16
	statepath      string
	encryptState   boolFlag
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

// Note - we use function pointers for subcommands so that subcommands like
// installSystemDaemon and uninstallSystemDaemon can be assigned platform-
// specific variants.

var subCommands = map[string]*func([]string) error{
	"install-system-daemon":   &installSystemDaemon,
	"uninstall-system-daemon": &uninstallSystemDaemon,
	"be-child":                &beChildFunc,
}

var beCLI func() // non-nil if CLI is linked in with the "ts_include_cli" build tag

// shouldRunCLI reports whether we should run the Tailscale CLI (cmd/tailscale)
// instead of the daemon (cmd/tailscaled) in the case when the two are linked
// together into one binary for space savings reasons.
func shouldRunCLI() bool {
	if beCLI == nil {
		// Not linked in with the "ts_include_cli" build tag.
		return false
	}
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "tailscale" {
		// The binary was named (or hardlinked) as "tailscale".
		return true
	}
	if envknob.Bool("TS_BE_CLI") {
		// The environment variable was set to force it.
		return true
	}
	return false
}

// Outbound Proxy hooks
var (
	hookRegisterOutboundProxyFlags feature.Hook[func()]
	hookOutboundProxyListen        feature.Hook[func() proxyStartFunc]
)

// proxyStartFunc is the type of the function returned by
// outboundProxyListen, to start the servers on the Listeners
// started by hookOutboundProxyListen.
type proxyStartFunc = func(logf logger.Logf, dialer *tsdial.Dialer)

func main() {
	envknob.PanicIfAnyEnvCheckedInInit()
	if shouldRunCLI() {
		beCLI()
		return
	}
	envknob.ApplyDiskConfig()
	applyIntegrationTestEnvKnob()

	defaultVerbosity := envknob.RegisterInt("TS_LOG_VERBOSITY")
	printVersion := false
	flag.IntVar(&args.verbose, "verbose", defaultVerbosity(), "log verbosity level; 0 is default, 1 or higher are increasingly verbose")
	flag.BoolVar(&args.cleanUp, "cleanup", false, "clean up system state and exit")
	if buildfeatures.HasDebug {
		flag.StringVar(&args.debug, "debug", "", "listen address ([ip]:port) of optional debug server")
	}
	flag.StringVar(&args.tunname, "tun", defaultTunName(), `tunnel interface name; use "userspace-networking" (beta) to not use TUN`)
	flag.Var(flagtype.PortValue(&args.port, defaultPort()), "port", "UDP port to listen on for WireGuard and peer-to-peer traffic; 0 means automatically select")
	flag.StringVar(&args.statepath, "state", "", "absolute path of state file; use 'kube:<secret-name>' to use Kubernetes secrets or 'arn:aws:ssm:...' to store in AWS SSM; use 'mem:' to not store state and register as an ephemeral node. If empty and --statedir is provided, the default is <statedir>/tailscaled.state. Default: "+paths.DefaultTailscaledStateFile())
	flag.Var(&args.encryptState, "encrypt-state", `encrypt the state file on disk; when not set encryption will be enabled if supported on this platform; uses TPM on Linux and Windows, on all other platforms this flag is not supported`)
	flag.StringVar(&args.statedir, "statedir", "", "path to directory for storage of config state, TLS certs, temporary incoming Taildrop files, etc. If empty, it's derived from --state when possible.")
	flag.StringVar(&args.socketpath, "socket", paths.DefaultTailscaledSocket(), "path of the service unix socket")
	flag.StringVar(&args.birdSocketPath, "bird-socket", "", "path of the bird unix socket")
	flag.BoolVar(&printVersion, "version", false, "print version information and exit")
	flag.BoolVar(&args.disableLogs, "no-logs-no-support", false, "disable log uploads; this also disables any technical support")
	flag.StringVar(&args.confFile, "config", "", "path to config file, or 'vm:user-data' to use the VM's user-data (EC2)")
	if f, ok := hookRegisterOutboundProxyFlags.GetOk(); ok {
		f()
	}

	if runtime.GOOS == "plan9" && os.Getenv("_NETSHELL_CHILD_") != "" {
		os.Args = []string{"tailscaled", "be-child", "plan9-netshell"}
	}

	if len(os.Args) > 1 {
		sub := os.Args[1]
		if fp, ok := subCommands[sub]; ok {
			if fp == nil {
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

	if fd, ok := envknob.LookupInt("TS_PARENT_DEATH_FD"); ok && fd > 2 {
		go dieOnPipeReadErrorOfFD(fd)
	}

	if printVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	if runtime.GOOS == "darwin" && os.Getuid() != 0 && !strings.Contains(args.tunname, "userspace-networking") && !args.cleanUp {
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
		if paths.MakeAutomaticStateDir() {
			d := paths.DefaultTailscaledStateDir()
			if d != "" {
				args.statedir = d
				if err := os.MkdirAll(d, 0700); err != nil {
					log.Fatalf("failed to create state directory: %v", err)
				}
			}
		} else {
			args.statepath = paths.DefaultTailscaledStateFile()
		}
	}

	if !args.encryptState.set {
		args.encryptState.v = defaultEncryptState()
	}
	if args.encryptState.v {
		if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
			log.SetFlags(0)
			log.Fatalf("--encrypt-state is not supported on %s", runtime.GOOS)
		}
		// Check if we have TPM support in this build.
		if !store.HasKnownProviderPrefix(store.TPMPrefix + "/") {
			log.SetFlags(0)
			log.Fatal("--encrypt-state is not supported in this build of tailscaled")
		}
		// Check if we have TPM access.
		if !hostinfo.New().TPM.Present() {
			log.SetFlags(0)
			log.Fatal("--encrypt-state is not supported on this device or a TPM is not accessible")
		}
		// Check for conflicting prefix in --state, like arn: or kube:.
		if args.statepath != "" && store.HasKnownProviderPrefix(args.statepath) {
			log.SetFlags(0)
			log.Fatal("--encrypt-state can only be used with --state set to a local file path")
		}
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
	var path string
	if args.statepath != "" {
		path = args.statepath
	}
	if path == "" && args.statedir != "" {
		path = filepath.Join(args.statedir, "tailscaled.state")
	}
	if path != "" && !store.HasKnownProviderPrefix(path) && args.encryptState.v {
		path = store.TPMPrefix + path
	}
	return path
}

// serverOptions is the configuration of the Tailscale node agent.
type serverOptions struct {
	// VarRoot is the Tailscale daemon's private writable
	// directory (usually "/var/lib/tailscale" on Linux) that
	// contains the "tailscaled.state" file, the "certs" directory
	// for TLS certs, and the "files" directory for incoming
	// Taildrop files before they're moved to a user directory.
	// If empty, Taildrop and TLS certs don't function.
	VarRoot string

	// LoginFlags specifies the LoginFlags to pass to the client.
	LoginFlags controlclient.LoginFlags
}

func ipnServerOpts() (o serverOptions) {
	goos := envknob.GOOS()

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
	case "windows":
		// Not those.
	}
	return o
}

var logPol *logpolicy.Policy // or nil if not used
var debugMux *http.ServeMux

func run() (err error) {
	var logf logger.Logf = log.Printf

	// Install an event bus as early as possible, so that it's
	// available universally when setting up everything else.
	sys := tsd.NewSystem()

	// Parse config, if specified, to fail early if it's invalid.
	var conf *conffile.Config
	if args.confFile != "" {
		conf, err = conffile.Load(args.confFile)
		if err != nil {
			return fmt.Errorf("error reading config file: %w", err)
		}
		sys.InitialConfig = conf
	}

	var netMon *netmon.Monitor
	isWinSvc := isWindowsService()
	if !isWinSvc {
		netMon, err = netmon.New(sys.Bus.Get(), logf)
		if err != nil {
			return fmt.Errorf("netmon.New: %w", err)
		}
		sys.Set(netMon)
	}

	var publicLogID logid.PublicID
	if buildfeatures.HasLogTail {

		pol := logpolicy.Options{
			Collection: logtail.CollectionNode,
			NetMon:     netMon,
			Health:     sys.HealthTracker.Get(),
			Bus:        sys.Bus.Get(),
		}.New()
		pol.SetVerbosityLevel(args.verbose)
		publicLogID = pol.PublicID
		logPol = pol
		defer func() {
			// Finish uploading logs after closing everything else.
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pol.Shutdown(ctx)
		}()
	}

	if err := envknob.ApplyDiskConfigError(); err != nil {
		log.Printf("Error reading environment config: %v", err)
	}

	if isWinSvc {
		// Run the IPN server from the Windows service manager.
		log.Printf("Running service...")
		if err := runWindowsService(logPol); err != nil {
			log.Printf("runservice: %v", err)
		}
		log.Printf("Service ended.")
		return nil
	}

	if envknob.Bool("TS_DEBUG_MEMORY") {
		logf = logger.RusagePrefixLog(logf)
	}
	logf = logger.RateLimitedFn(logf, 5*time.Second, 5, 100)

	if envknob.Bool("TS_PLEASE_PANIC") {
		panic("TS_PLEASE_PANIC asked us to panic")
	}
	// Always clean up, even if we're going to run the server. This covers cases
	// such as when a system was rebooted without shutting down, or tailscaled
	// crashed, and would for example restore system DNS configuration.
	dns.CleanUp(logf, netMon, sys.Bus.Get(), sys.HealthTracker.Get(), args.tunname)
	router.CleanUp(logf, netMon, args.tunname)
	// If the cleanUp flag was passed, then exit.
	if args.cleanUp {
		return nil
	}

	if args.statepath == "" && args.statedir == "" {
		log.Fatalf("--statedir (or at least --state) is required")
	}
	if err := trySynologyMigration(statePathOrDefault()); err != nil {
		log.Printf("error in synology migration: %v", err)
	}

	if buildfeatures.HasDebug && args.debug != "" {
		debugMux = hookNewDebugMux.Get()()
	}

	if f, ok := hookSetSysDrive.GetOk(); ok {
		f(sys, logf)
	}

	if app := envknob.App(); app != "" {
		hostinfo.SetApp(app)
	}

	return startIPNServer(context.Background(), logf, publicLogID, sys)
}

var (
	hookSetSysDrive           feature.Hook[func(*tsd.System, logger.Logf)]
	hookSetWgEnginConfigDrive feature.Hook[func(*wgengine.Config, logger.Logf)]
)

var sigPipe os.Signal // set by sigpipe.go

// logID may be the zero value if logging is not in use.
func startIPNServer(ctx context.Context, logf logger.Logf, logID logid.PublicID, sys *tsd.System) error {
	ln, err := safesocket.Listen(args.socketpath)
	if err != nil {
		return fmt.Errorf("safesocket.Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Exit gracefully by cancelling the ipnserver context in most common cases:
	// interrupted from the TTY or killed by a service manager.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	// SIGPIPE sometimes gets generated when CLIs disconnect from
	// tailscaled. The default action is to terminate the process, we
	// want to keep running.
	if sigPipe != nil {
		signal.Ignore(sigPipe)
	}
	wgEngineCreated := make(chan struct{})
	go func() {
		var wgEngineClosed <-chan struct{}
		wgEngineCreated := wgEngineCreated // local shadow
		for {
			select {
			case s := <-interrupt:
				logf("tailscaled got signal %v; shutting down", s)
				cancel()
				return
			case <-wgEngineClosed:
				logf("wgengine has been closed; shutting down")
				cancel()
				return
			case <-wgEngineCreated:
				wgEngineClosed = sys.Engine.Get().Done()
				wgEngineCreated = nil
			case <-ctx.Done():
				return
			}
		}
	}()

	srv := ipnserver.New(logf, logID, sys.Bus.Get(), sys.NetMon.Get())
	if buildfeatures.HasDebug && debugMux != nil {
		debugMux.HandleFunc("/debug/ipn", srv.ServeHTMLStatus)
	}
	var lbErr syncs.AtomicValue[error]

	go func() {
		t0 := time.Now()
		if s, ok := envknob.LookupInt("TS_DEBUG_BACKEND_DELAY_SEC"); ok {
			d := time.Duration(s) * time.Second
			logf("sleeping %v before starting backend...", d)
			select {
			case <-time.After(d):
				logf("slept %v; starting backend...", d)
			case <-ctx.Done():
				return
			}
		}
		lb, err := getLocalBackend(ctx, logf, logID, sys)
		if err == nil {
			logf("got LocalBackend in %v", time.Since(t0).Round(time.Millisecond))
			if lb.Prefs().Valid() {
				if err := lb.Start(ipn.Options{}); err != nil {
					logf("LocalBackend.Start: %v", err)
					lb.Shutdown()
					lbErr.Store(err)
					cancel()
					return
				}
			}
			srv.SetLocalBackend(lb)
			close(wgEngineCreated)
			return
		}
		lbErr.Store(err) // before the following cancel
		cancel()         // make srv.Run below complete
	}()

	err = srv.Run(ctx, ln)

	if err != nil && lbErr.Load() != nil {
		return fmt.Errorf("getLocalBackend error: %v", lbErr.Load())
	}

	// Cancelation is not an error: it is the only way to stop ipnserver.
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("ipnserver.Run: %w", err)
	}

	return nil
}

var (
	hookNewNetstack feature.Hook[func(_ logger.Logf, _ *tsd.System, onlyNetstack bool) (tsd.NetstackImpl, error)]
)

// logID may be the zero value if logging is not in use.
func getLocalBackend(ctx context.Context, logf logger.Logf, logID logid.PublicID, sys *tsd.System) (_ *ipnlocal.LocalBackend, retErr error) {
	if logPol != nil {
		logPol.Logtail.SetNetMon(sys.NetMon.Get())
	}

	var startProxy proxyStartFunc
	if listen, ok := hookOutboundProxyListen.GetOk(); ok {
		startProxy = listen()
	}

	dialer := &tsdial.Dialer{Logf: logf} // mutated below (before used)
	dialer.SetBus(sys.Bus.Get())
	sys.Set(dialer)

	onlyNetstack, err := createEngine(logf, sys)
	if err != nil {
		return nil, fmt.Errorf("createEngine: %w", err)
	}
	if onlyNetstack && !buildfeatures.HasNetstack {
		return nil, errors.New("userspace-networking support is not compiled in to this binary")
	}
	if buildfeatures.HasDebug && debugMux != nil {
		if ms, ok := sys.MagicSock.GetOK(); ok {
			debugMux.HandleFunc("/debug/magicsock", ms.ServeHTTPDebug)
		}
		go runDebugServer(logf, debugMux, args.debug)
	}

	var ns tsd.NetstackImpl // or nil if not linked in
	if newNetstack, ok := hookNewNetstack.GetOk(); ok {
		ns, err = newNetstack(logf, sys, onlyNetstack)
		if err != nil {
			return nil, fmt.Errorf("newNetstack: %w", err)
		}
	}

	if startProxy != nil {
		go startProxy(logf, dialer)
	}

	opts := ipnServerOpts()

	store, err := store.New(logf, statePathOrDefault())
	if err != nil {
		return nil, fmt.Errorf("store.New: %w", err)
	}
	sys.Set(store)

	if w, ok := sys.Tun.GetOK(); ok {
		w.Start()
	}

	lb, err := ipnlocal.NewLocalBackend(logf, logID, sys, opts.LoginFlags)
	if err != nil {
		return nil, fmt.Errorf("ipnlocal.NewLocalBackend: %w", err)
	}
	lb.SetVarRoot(opts.VarRoot)
	if logPol != nil {
		lb.SetLogFlusher(logPol.Logtail.StartFlush)
	}
	if root := lb.TailscaleVarRoot(); root != "" {
		dnsfallback.SetCachePath(filepath.Join(root, "derpmap.cached.json"), logf)
	}
	if f, ok := hookConfigureWebClient.GetOk(); ok {
		f(lb)
	}

	if ns != nil {
		if err := ns.Start(lb); err != nil {
			log.Fatalf("failed to start netstack: %v", err)
		}
	}
	return lb, nil
}

var hookConfigureWebClient feature.Hook[func(*ipnlocal.LocalBackend)]

// createEngine tries to the wgengine.Engine based on the order of tunnels
// specified in the command line flags.
//
// onlyNetstack is true if the user has explicitly requested that we use netstack
// for all networking.
func createEngine(logf logger.Logf, sys *tsd.System) (onlyNetstack bool, err error) {
	if args.tunname == "" {
		return false, errors.New("no --tun value specified")
	}
	var errs []error
	for _, name := range strings.Split(args.tunname, ",") {
		logf("wgengine.NewUserspaceEngine(tun %q) ...", name)
		onlyNetstack, err = tryEngine(logf, sys, name)
		if err == nil {
			return onlyNetstack, nil
		}
		logf("wgengine.NewUserspaceEngine(tun %q) error: %v", name, err)
		errs = append(errs, err)
	}
	return false, errors.Join(errs...)
}

// handleSubnetsInNetstack reports whether netstack should handle subnet routers
// as opposed to the OS. We do this if the OS doesn't support subnet routers
// (e.g. Windows) or if the user has explicitly requested it (e.g.
// --tun=userspace-networking).
func handleSubnetsInNetstack() bool {
	if v, ok := envknob.LookupBool("TS_DEBUG_NETSTACK_SUBNETS"); ok {
		return v
	}
	if distro.Get() == distro.Synology {
		return true
	}
	switch runtime.GOOS {
	case "windows", "darwin", "freebsd", "openbsd", "solaris", "illumos":
		// Enable on Windows and tailscaled-on-macOS (this doesn't
		// affect the GUI clients), and on FreeBSD.
		return true
	}
	return false
}

var tstunNew = tstun.New

func tryEngine(logf logger.Logf, sys *tsd.System, name string) (onlyNetstack bool, err error) {
	conf := wgengine.Config{
		ListenPort:    args.port,
		NetMon:        sys.NetMon.Get(),
		HealthTracker: sys.HealthTracker.Get(),
		Metrics:       sys.UserMetricsRegistry(),
		Dialer:        sys.Dialer.Get(),
		SetSubsystem:  sys.Set,
		ControlKnobs:  sys.ControlKnobs(),
		EventBus:      sys.Bus.Get(),
	}
	if f, ok := hookSetWgEnginConfigDrive.GetOk(); ok {
		f(&conf, logf)
	}

	sys.HealthTracker.Get().SetMetricsRegistry(sys.UserMetricsRegistry())

	onlyNetstack = name == "userspace-networking"
	netstackSubnetRouter := onlyNetstack // but mutated later on some platforms
	netns.SetEnabled(!onlyNetstack)

	if args.birdSocketPath != "" && createBIRDClient != nil {
		log.Printf("Connecting to BIRD at %s ...", args.birdSocketPath)
		conf.BIRDClient, err = createBIRDClient(args.birdSocketPath)
		if err != nil {
			return false, fmt.Errorf("createBIRDClient: %w", err)
		}
	}
	if onlyNetstack {
		if runtime.GOOS == "linux" && distro.Get() == distro.Synology {
			// On Synology in netstack mode, still init a DNS
			// manager (directManager) to avoid the health check
			// warnings in 'tailscale status' about DNS base
			// configuration being unavailable (from the noop
			// manager). More in Issue 4017.
			// TODO(bradfitz): add a Synology-specific DNS manager.
			conf.DNS, err = dns.NewOSConfigurator(logf, sys.HealthTracker.Get(), sys.PolicyClientOrDefault(), sys.ControlKnobs(), "") // empty interface name
			if err != nil {
				return false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
			}
		}
	} else {
		dev, devName, err := tstunNew(logf, name)
		if err != nil {
			tstun.Diagnose(logf, name, err)
			return false, fmt.Errorf("tstun.New(%q): %w", name, err)
		}
		conf.Tun = dev
		if strings.HasPrefix(name, "tap:") {
			conf.IsTAP = true
			e, err := wgengine.NewUserspaceEngine(logf, conf)
			if err != nil {
				return false, err
			}
			sys.Set(e)
			return false, err
		}

		if runtime.GOOS == "plan9" {
			// TODO(bradfitz): why don't we do this on all platforms?
			// We should. Doing it just on plan9 for now conservatively.
			sys.NetMon.Get().SetTailscaleInterfaceName(devName)
		}

		r, err := router.New(logf, dev, sys.NetMon.Get(), sys.HealthTracker.Get(), sys.Bus.Get())
		if err != nil {
			dev.Close()
			return false, fmt.Errorf("creating router: %w", err)
		}

		d, err := dns.NewOSConfigurator(logf, sys.HealthTracker.Get(), sys.PolicyClientOrDefault(), sys.ControlKnobs(), devName)
		if err != nil {
			dev.Close()
			r.Close()
			return false, fmt.Errorf("dns.NewOSConfigurator: %w", err)
		}
		conf.DNS = d
		conf.Router = r
		if handleSubnetsInNetstack() {
			netstackSubnetRouter = true
		}
		sys.Set(conf.Router)
	}
	e, err := wgengine.NewUserspaceEngine(logf, conf)
	if err != nil {
		return onlyNetstack, err
	}
	e = wgengine.NewWatchdog(e)
	sys.Set(e)
	sys.NetstackRouter.Set(netstackSubnetRouter)

	return onlyNetstack, nil
}

var hookNewDebugMux feature.Hook[func() *http.ServeMux]

func servePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	varz.Handler(w, r)
	clientmetric.WritePrometheusExpositionFormat(w)
}

func runDebugServer(logf logger.Logf, mux *http.ServeMux, addr string) {
	if !buildfeatures.HasDebug {
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("debug server: %v", err)
	}
	if strings.HasSuffix(addr, ":0") {
		// Log kernel-selected port number so integration tests
		// can find it portably.
		logf("DEBUG-ADDR=%v", ln.Addr())
	}
	srv := &http.Server{
		Handler: mux,
	}
	if err := srv.Serve(ln); err != nil {
		log.Fatal(err)
	}
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

// dieOnPipeReadErrorOfFD reads from the pipe named by fd and exit the process
// when the pipe becomes readable. We use this in tests as a somewhat more
// portable mechanism for the Linux PR_SET_PDEATHSIG, which we wish existed on
// macOS. This helps us clean up straggler tailscaled processes when the parent
// test driver dies unexpectedly.
func dieOnPipeReadErrorOfFD(fd int) {
	f := os.NewFile(uintptr(fd), "TS_PARENT_DEATH_FD")
	f.Read(make([]byte, 1))
	os.Exit(1)
}

// applyIntegrationTestEnvKnob applies the tailscaled.env=... environment
// variables specified on the Linux kernel command line, if the VM is being
// run in NATLab integration tests.
//
// They're specified as: tailscaled.env=FOO=bar tailscaled.env=BAR=baz
func applyIntegrationTestEnvKnob() {
	if runtime.GOOS != "linux" || !hostinfo.IsNATLabGuestVM() {
		return
	}
	cmdLine, _ := os.ReadFile("/proc/cmdline")
	for _, s := range strings.Fields(string(cmdLine)) {
		suf, ok := strings.CutPrefix(s, "tailscaled.env=")
		if !ok {
			continue
		}
		if k, v, ok := strings.Cut(suf, "="); ok {
			envknob.Setenv(k, v)
		}
	}
}

func defaultEncryptState() bool {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		// TPM encryption is only configurable on Windows and Linux. Other
		// platforms either use system APIs and are not configurable
		// (Android/Apple), or don't support any form of encryption yet
		// (plan9/FreeBSD/etc).
		return false
	}
	v, _ := policyclient.Get().GetBoolean(pkey.EncryptState, feature.TPMAvailable())
	return v
}
