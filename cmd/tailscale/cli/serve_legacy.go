// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_omit_serve

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/local"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/slicesx"
	"tailscale.com/version"
)

func init() {
	maybeServeCmd = serveCmd
}

var serveCmd = func() *ffcli.Command {
	se := &serveEnv{lc: &localClient}
	// previously used to serve legacy newFunnelCommand unless useWIPCode is true
	// change is limited to make a revert easier and full cleanup to come after the relase.
	// TODO(tylersmalley): cleanup and removal of newServeLegacyCommand as of 2023-10-16
	return newServeV2Command(se, serve)
}

// newServeLegacyCommand returns a new "serve" subcommand using e as its environment.
func newServeLegacyCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:      "serve",
		ShortHelp: "Serve content and local servers",
		ShortUsage: strings.Join([]string{
			"tailscale serve http:<port> <mount-point> <source> [off]",
			"tailscale serve https:<port> <mount-point> <source> [off]",
			"tailscale serve tcp:<port> tcp://localhost:<local-port> [off]",
			"tailscale serve tls-terminated-tcp:<port> tcp://localhost:<local-port> [off]",
			"tailscale serve status [--json]",
			"tailscale serve reset",
		}, "\n"),
		LongHelp: strings.TrimSpace(`
*** BETA; all of this is subject to change ***

The 'tailscale serve' set of commands allows you to serve
content and local servers from your Tailscale node to
your tailnet.

You can also choose to enable the Tailscale Funnel with:
'tailscale funnel on'. Funnel allows you to publish
a 'tailscale serve' server publicly, open to the entire
internet. See https://tailscale.com/funnel.

EXAMPLES
  - To proxy requests to a web server at 127.0.0.1:3000:
    $ tailscale serve https:443 / http://127.0.0.1:3000

    Or, using the default port (443):
    $ tailscale serve https / http://127.0.0.1:3000

  - To serve a single file or a directory of files:
    $ tailscale serve https / /home/alice/blog/index.html
    $ tailscale serve https /images/ /home/alice/blog/images

  - To serve simple static text:
    $ tailscale serve https:8080 / text:"Hello, world!"

  - To serve over HTTP (tailnet only):
    $ tailscale serve http:80 / http://127.0.0.1:3000

    Or, using the default port (80):
    $ tailscale serve http / http://127.0.0.1:3000

  - To forward incoming TCP connections on port 2222 to a local TCP server on
    port 22 (e.g. to run OpenSSH in parallel with Tailscale SSH):
    $ tailscale serve tcp:2222 tcp://localhost:22

  - To accept TCP TLS connections (terminated within tailscaled) proxied to a
    local plaintext server on port 80:
    $ tailscale serve tls-terminated-tcp:443 tcp://localhost:80
`),
		Exec: e.runServe,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "Show current serve/funnel status",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
			},
			{
				Name:      "reset",
				Exec:      e.runServeReset,
				ShortHelp: "Reset current serve/funnel config",
				FlagSet:   e.newFlags("serve-reset", nil),
			},
		},
	}
}

// errHelp is standard error text that prompts users to
// run `serve --help` for information on how to use serve.
var errHelp = errors.New("try `tailscale serve --help` for usage info")

func (e *serveEnv) newFlags(name string, setup func(fs *flag.FlagSet)) *flag.FlagSet {
	onError, out := flag.ExitOnError, Stderr
	if e.testFlagOut != nil {
		onError, out = flag.ContinueOnError, e.testFlagOut
	}
	fs := flag.NewFlagSet(name, onError)
	fs.SetOutput(out)
	if setup != nil {
		setup(fs)
	}
	return fs
}

// localServeClient is an interface conforming to the subset of
// local.Client. It includes only the methods used by the
// serve command.
//
// The purpose of this interface is to allow tests to provide a mock.
type localServeClient interface {
	StatusWithoutPeers(context.Context) (*ipnstate.Status, error)
	GetServeConfig(context.Context) (*ipn.ServeConfig, error)
	SetServeConfig(context.Context, *ipn.ServeConfig) error
	QueryFeature(ctx context.Context, feature string) (*tailcfg.QueryFeatureResponse, error)
	WatchIPNBus(ctx context.Context, mask ipn.NotifyWatchOpt) (*local.IPNBusWatcher, error)
	IncrementCounter(ctx context.Context, name string, delta int) error
	GetPrefs(ctx context.Context) (*ipn.Prefs, error)
	EditPrefs(ctx context.Context, mp *ipn.MaskedPrefs) (*ipn.Prefs, error)
}

// serveEnv is the environment the serve command runs within. All I/O should be
// done via serveEnv methods so that it can be faked out for tests.
// Calls to localClient should be done via the lc field, which is an interface
// that can be faked out for tests.
//
// It also contains the flags, as registered with newServeCommand.
type serveEnv struct {
	// v1 flags
	json bool // output JSON (status only for now)

	// v2 specific flags
	bg               bgBoolFlag          // background mode
	setPath          string              // serve path
	https            uint                // HTTP port
	http             uint                // HTTP port
	tcp              uint                // TCP port
	tlsTerminatedTCP uint                // a TLS terminated TCP port
	subcmd           serveMode           // subcommand
	yes              bool                // update without prompt
	service          tailcfg.ServiceName // service name
	tun              bool                // redirect traffic to OS for service
	allServices      bool                // apply config file to all services

	lc localServeClient // localClient interface, specific to serve

	// optional stuff for tests:
	testFlagOut io.Writer
	testStdout  io.Writer
	testStderr  io.Writer
}

// getSelfDNSName returns the DNS name of the current node.
// The trailing dot is removed.
// Returns an error if local client status fails.
func (e *serveEnv) getSelfDNSName(ctx context.Context) (string, error) {
	st, err := e.getLocalClientStatusWithoutPeers(ctx)
	if err != nil {
		return "", fmt.Errorf("getting client status: %w", err)
	}
	return strings.TrimSuffix(st.Self.DNSName, "."), nil
}

// getLocalClientStatusWithoutPeers returns the Status of the local client
// without any peers in the response.
//
// Returns error if unable to reach tailscaled or if self node is nil.
//
// Exits if status is not running or starting.
func (e *serveEnv) getLocalClientStatusWithoutPeers(ctx context.Context) (*ipnstate.Status, error) {
	st, err := e.lc.StatusWithoutPeers(ctx)
	if err != nil {
		return nil, fixTailscaledConnectError(err)
	}
	description, ok := isRunningOrStarting(st)
	if !ok {
		fmt.Fprintf(Stderr, "%s\n", description)
		os.Exit(1)
	}
	if st.Self == nil {
		return nil, errors.New("no self node")
	}
	return st, nil
}

// runServe is the entry point for the "serve" subcommand, managing Web
// serve config types like proxy, path, and text.
//
// Examples:
// - tailscale serve http / http://localhost:3000
// - tailscale serve https / http://localhost:3000
// - tailscale serve https /images/ /var/www/images/
// - tailscale serve https:10000 /motd.txt text:"Hello, world!"
// - tailscale serve tcp:2222 tcp://localhost:22
// - tailscale serve tls-terminated-tcp:443 tcp://localhost:80
func (e *serveEnv) runServe(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return flag.ErrHelp
	}

	// Undocumented debug command (not using ffcli subcommands) to set raw
	// configs from stdin for now (2022-11-13).
	if len(args) == 1 && args[0] == "set-raw" {
		valb, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		sc := new(ipn.ServeConfig)
		if err := json.Unmarshal(valb, sc); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		return e.lc.SetServeConfig(ctx, sc)
	}

	srcType, srcPortStr, found := strings.Cut(args[0], ":")
	if !found {
		if srcType == "https" && srcPortStr == "" {
			// Default https port to 443.
			srcPortStr = "443"
		} else if srcType == "http" && srcPortStr == "" {
			// Default http port to 80.
			srcPortStr = "80"
		} else {
			return flag.ErrHelp
		}
	}

	turnOff := "off" == args[len(args)-1]

	if len(args) < 2 || ((srcType == "https" || srcType == "http") && !turnOff && len(args) < 3) {
		fmt.Fprintf(Stderr, "error: invalid number of arguments\n\n")
		return errHelp
	}

	if srcType == "https" && !turnOff {
		// Running serve with https requires that the tailnet has enabled
		// https cert provisioning. Send users through an interactive flow
		// to enable this if not already done.
		//
		// TODO(sonia,tailscale/corp#10577): The interactive feature flow
		// is behind a control flag. If the tailnet doesn't have the flag
		// on, enableFeatureInteractive will error. For now, we hide that
		// error and maintain the previous behavior (prior to 2023-08-15)
		// of letting them edit the serve config before enabling certs.
		e.enableFeatureInteractive(ctx, "serve", tailcfg.CapabilityHTTPS)
	}

	srcPort, err := parseServePort(srcPortStr)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", srcPortStr, err)
	}

	switch srcType {
	case "https", "http":
		mount, err := cleanMountPoint(args[1])
		if err != nil {
			return err
		}
		if turnOff {
			return e.handleWebServeRemove(ctx, srcPort, mount)
		}
		useTLS := srcType == "https"
		return e.handleWebServe(ctx, srcPort, useTLS, mount, args[2])
	case "tcp", "tls-terminated-tcp":
		if turnOff {
			return e.handleTCPServeRemove(ctx, srcPort)
		}
		return e.handleTCPServe(ctx, srcType, srcPort, args[1])
	default:
		fmt.Fprintf(Stderr, "error: invalid serve type %q\n", srcType)
		fmt.Fprint(Stderr, "must be one of: http:<port>, https:<port>, tcp:<port> or tls-terminated-tcp:<port>\n\n", srcType)
		return errHelp
	}
}

// handleWebServe handles the "tailscale serve (http/https):..." subcommand. It
// configures the serve config to forward HTTPS connections to the given source.
//
// Examples:
//   - tailscale serve http / http://localhost:3000
//   - tailscale serve https / http://localhost:3000
//   - tailscale serve https:8443 /files/ /home/alice/shared-files/
//   - tailscale serve https:10000 /motd.txt text:"Hello, world!"
func (e *serveEnv) handleWebServe(ctx context.Context, srvPort uint16, useTLS bool, mount, source string) error {
	h := new(ipn.HTTPHandler)

	ts, _, _ := strings.Cut(source, ":")
	switch {
	case ts == "text":
		text := strings.TrimPrefix(source, "text:")
		if text == "" {
			return errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = text
	case isProxyTarget(source):
		t, err := expandProxyTarget(source)
		if err != nil {
			return err
		}
		h.Proxy = t
	default: // assume path
		if version.IsSandboxedMacOS() {
			// don't allow path serving for now on macOS (2022-11-15)
			return fmt.Errorf("path serving is not supported if sandboxed on macOS")
		}
		if !filepath.IsAbs(source) {
			fmt.Fprintf(Stderr, "error: path must be absolute\n\n")
			return errHelp
		}
		source = filepath.Clean(source)
		fi, err := os.Stat(source)
		if err != nil {
			fmt.Fprintf(Stderr, "error: invalid path: %v\n\n", err)
			return errHelp
		}
		if fi.IsDir() && !strings.HasSuffix(mount, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mount += "/"
		}
		h.Path = source
	}

	cursc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	if sc.IsTCPForwardingOnPort(srvPort, noService) {
		fmt.Fprintf(Stderr, "error: cannot serve web; already serving TCP\n")
		return errHelp
	}

	sc.SetWebHandler(h, dnsName, srvPort, mount, useTLS, noService.String())

	if !reflect.DeepEqual(cursc, sc) {
		if err := e.lc.SetServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

// isProxyTarget reports whether source is a valid proxy target.
func isProxyTarget(source string) bool {
	if strings.HasPrefix(source, "http://") ||
		strings.HasPrefix(source, "https://") ||
		strings.HasPrefix(source, "https+insecure://") {
		return true
	}
	// support "localhost:3000", for example
	_, portStr, ok := strings.Cut(source, ":")
	if ok && allNumeric(portStr) {
		return true
	}
	return false
}

// allNumeric reports whether s only comprises of digits
// and has at least one digit.
func allNumeric(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// handleWebServeRemove removes a web handler from the serve config.
// The srvPort argument is the serving port and the mount argument is
// the mount point or registered path to remove.
func (e *serveEnv) handleWebServeRemove(ctx context.Context, srvPort uint16, mount string) error {
	sc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	if sc == nil {
		return errors.New("error: serve config does not exist")
	}
	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}
	if sc.IsTCPForwardingOnPort(srvPort, noService) {
		return errors.New("cannot remove web handler; currently serving TCP")
	}
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))
	if !sc.WebHandlerExists(noService, hp, mount) {
		return errors.New("error: handler does not exist")
	}
	sc.RemoveWebHandler(dnsName, srvPort, []string{mount}, false)
	if err := e.lc.SetServeConfig(ctx, sc); err != nil {
		return err
	}
	return nil
}

func cleanMountPoint(mount string) (string, error) {
	if mount == "" {
		return "", errors.New("mount point cannot be empty")
	}
	mount = cleanMinGWPathConversionIfNeeded(mount)
	if !strings.HasPrefix(mount, "/") {
		mount = "/" + mount
	}
	c := path.Clean(mount)
	if mount == c || mount == c+"/" {
		return mount, nil
	}
	return "", fmt.Errorf("invalid mount point %q", mount)
}

// cleanMinGWPathConversionIfNeeded strips the EXEPATH prefix from the given
// path if the path is a MinGW(ish) (Windows) shell arg.
//
// MinGW(ish) (Windows) shells perform POSIX-to-Windows path conversion
// converting the leading "/" of any shell arg to the EXEPATH, which mangles the
// mount point. Strip the EXEPATH prefix if it exists. #7963
//
// "/C:/Program Files/Git/foo" -> "/foo"
func cleanMinGWPathConversionIfNeeded(path string) string {
	// Only do this on Windows.
	if runtime.GOOS != "windows" {
		return path
	}
	if _, ok := os.LookupEnv("MSYSTEM"); ok {
		exepath := filepath.ToSlash(os.Getenv("EXEPATH"))
		path = strings.TrimPrefix(path, exepath)
	}
	return path
}

func expandProxyTarget(source string) (string, error) {
	if !strings.Contains(source, "://") {
		source = "http://" + source
	}
	u, err := url.ParseRequestURI(source)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "https+insecure":
		// ok
	default:
		return "", fmt.Errorf("must be a URL starting with http://, https://, or https+insecure://")
	}

	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if port == 0 || err != nil {
		return "", fmt.Errorf("invalid port %q: %w", u.Port(), err)
	}

	host := u.Hostname()
	switch host {
	case "localhost", "127.0.0.1":
		host = "127.0.0.1"
	default:
		return "", fmt.Errorf("only localhost or 127.0.0.1 proxies are currently supported")
	}
	url := u.Scheme + "://" + host
	if u.Port() != "" {
		url += ":" + u.Port()
	}
	url += u.Path
	return url, nil
}

// handleTCPServe handles the "tailscale serve tls-terminated-tcp:..." subcommand.
// It configures the serve config to forward TCP connections to the
// given source.
//
// Examples:
//   - tailscale serve tcp:2222 tcp://localhost:22
//   - tailscale serve tls-terminated-tcp:8443 tcp://localhost:8080
func (e *serveEnv) handleTCPServe(ctx context.Context, srcType string, srcPort uint16, dest string) error {
	var terminateTLS bool
	switch srcType {
	case "tcp":
		terminateTLS = false
	case "tls-terminated-tcp":
		terminateTLS = true
	default:
		fmt.Fprintf(Stderr, "error: invalid TCP source %q\n\n", dest)
		return errHelp
	}

	dstURL, err := url.Parse(dest)
	if err != nil {
		fmt.Fprintf(Stderr, "error: invalid TCP source %q: %v\n\n", dest, err)
		return errHelp
	}
	host, dstPortStr, err := net.SplitHostPort(dstURL.Host)
	if err != nil {
		fmt.Fprintf(Stderr, "error: invalid TCP source %q: %v\n\n", dest, err)
		return errHelp
	}

	switch host {
	case "localhost", "127.0.0.1":
		// ok
	default:
		fmt.Fprintf(Stderr, "error: invalid TCP source %q\n", dest)
		fmt.Fprint(Stderr, "must be one of: localhost or 127.0.0.1\n\n", dest)
		return errHelp
	}

	if p, err := strconv.ParseUint(dstPortStr, 10, 16); p == 0 || err != nil {
		fmt.Fprintf(Stderr, "error: invalid port %q\n\n", dstPortStr)
		return errHelp
	}

	cursc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	fwdAddr := "127.0.0.1:" + dstPortStr

	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}

	if sc.IsServingWeb(srcPort, noService) {
		return fmt.Errorf("cannot serve TCP; already serving web on %d", srcPort)
	}

	sc.SetTCPForwarding(srcPort, fwdAddr, terminateTLS, dnsName)

	if !reflect.DeepEqual(cursc, sc) {
		if err := e.lc.SetServeConfig(ctx, sc); err != nil {
			return err
		}
	}

	return nil
}

// handleTCPServeRemove removes the TCP forwarding configuration for the
// given srvPort, or serving port.
func (e *serveEnv) handleTCPServeRemove(ctx context.Context, src uint16) error {
	cursc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	if sc.IsServingWeb(src, noService) {
		return fmt.Errorf("unable to remove; serving web, not TCP forwarding on serve port %d", src)
	}
	if ph := sc.GetTCPPortHandler(src, noService); ph != nil {
		sc.RemoveTCPForwarding(noService, src)
		return e.lc.SetServeConfig(ctx, sc)
	}
	return errors.New("error: serve config does not exist")
}

// runServeStatus is the entry point for the "serve status"
// subcommand and prints the current serve config.
//
// Examples:
//   - tailscale status
//   - tailscale status --json
//
// TODO(tyler,marwan,sonia): `status` should also report foreground configs,
// currently only reports background config.
func (e *serveEnv) runServeStatus(ctx context.Context, args []string) error {
	sc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	if e.json {
		j, err := json.MarshalIndent(sc, "", "  ")
		if err != nil {
			return err
		}
		j = append(j, '\n')
		e.stdout().Write(j)
		return nil
	}
	printFunnelStatus(ctx)
	if sc == nil || (len(sc.TCP) == 0 && len(sc.Web) == 0 && len(sc.AllowFunnel) == 0) {
		printf("No serve config\n")
		return nil
	}
	st, err := e.getLocalClientStatusWithoutPeers(ctx)
	if err != nil {
		return err
	}
	if sc.IsTCPForwardingAny() {
		if err := printTCPStatusTree(ctx, sc, st); err != nil {
			return err
		}
		printf("\n")
	}
	for hp := range sc.Web {
		err := e.printWebStatusTree(sc, hp)
		if err != nil {
			return err
		}
		printf("\n")
	}
	printFunnelWarning(sc)
	return nil
}

func printTCPStatusTree(ctx context.Context, sc *ipn.ServeConfig, st *ipnstate.Status) error {
	dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
	for p, h := range sc.TCP {
		if h.TCPForward == "" {
			continue
		}
		hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(p))))
		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}
		fStatus := "tailnet only"
		if sc.AllowFunnel[hp] {
			fStatus = "Funnel on"
		}
		printf("|-- tcp://%s (%s, %s)\n", hp, tlsStatus, fStatus)
		for _, a := range st.TailscaleIPs {
			ipp := net.JoinHostPort(a.String(), strconv.Itoa(int(p)))
			printf("|-- tcp://%s\n", ipp)
		}
		printf("|--> tcp://%s\n", h.TCPForward)
	}
	return nil
}

func (e *serveEnv) printWebStatusTree(sc *ipn.ServeConfig, hp ipn.HostPort) error {
	// No-op if no serve config
	if sc == nil {
		return nil
	}
	fStatus := "tailnet only"
	if sc.AllowFunnel[hp] {
		fStatus = "Funnel on"
	}
	host, portStr, _ := net.SplitHostPort(string(hp))

	port, err := parseServePort(portStr)
	if err != nil {
		return fmt.Errorf("invalid port %q: %w", portStr, err)
	}

	scheme := "https"
	if sc.IsServingHTTP(port, noService) {
		scheme = "http"
	}

	portPart := ":" + portStr
	if scheme == "http" && portStr == "80" ||
		scheme == "https" && portStr == "443" {
		portPart = ""
	}
	if scheme == "http" {
		hostname, _, _ := strings.Cut(host, ".")
		printf("%s://%s%s (%s)\n", scheme, hostname, portPart, fStatus)
	}
	printf("%s://%s%s (%s)\n", scheme, host, portPart, fStatus)
	srvTypeAndDesc := func(h *ipn.HTTPHandler) (string, string) {
		switch {
		case h.Path != "":
			return "path", h.Path
		case h.Proxy != "":
			return "proxy", h.Proxy
		case h.Text != "":
			return "text", "\"" + elipticallyTruncate(h.Text, 20) + "\""
		}
		return "", ""
	}

	mounts := slicesx.MapKeys(sc.Web[hp].Handlers)
	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i]) < len(mounts[j])
	})
	maxLen := len(mounts[len(mounts)-1])

	for _, m := range mounts {
		h := sc.Web[hp].Handlers[m]
		t, d := srvTypeAndDesc(h)
		printf("%s %s%s %-5s %s\n", "|--", m, strings.Repeat(" ", maxLen-len(m)), t, d)
	}

	return nil
}

func elipticallyTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// runServeReset clears out the current serve config.
//
// Usage:
//   - tailscale serve reset
func (e *serveEnv) runServeReset(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return flag.ErrHelp
	}
	sc := new(ipn.ServeConfig)
	return e.lc.SetServeConfig(ctx, sc)
}

// parseServePort parses a port number from a string and returns it as a
// uint16. It returns an error if the port number is invalid or zero.
func parseServePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	if p == 0 {
		return 0, errors.New("port number must be non-zero")
	}
	return uint16(p), nil
}

// enableFeatureInteractive sends the node's user through an interactive
// flow to enable a feature, such as Funnel, on their tailnet.
//
// hasRequiredCapabilities should be provided as a function that checks
// whether a slice of node capabilities encloses the necessary values
// needed to use the feature.
//
// If err is returned empty, the feature has been successfully enabled.
//
// If err is returned non-empty, the client failed to query the control
// server for information about how to enable the feature.
//
// If the feature cannot be enabled, enableFeatureInteractive terminates
// the CLI process.
//
// 2023-08-09: The only valid feature values are "serve" and "funnel".
// This can be moved to some CLI lib when expanded past serve/funnel.
func (e *serveEnv) enableFeatureInteractive(ctx context.Context, feature string, caps ...tailcfg.NodeCapability) (err error) {
	st, err := e.getLocalClientStatusWithoutPeers(ctx)
	if err != nil {
		return fmt.Errorf("getting client status: %w", err)
	}
	if st.Self == nil {
		return errors.New("no self node")
	}
	hasCaps := func() bool {
		for _, c := range caps {
			if !st.Self.HasCap(c) {
				return false
			}
		}
		return true
	}
	if hasCaps() {
		return nil // already enabled
	}
	info, err := e.lc.QueryFeature(ctx, feature)
	if err != nil {
		return err
	}
	if info.Complete {
		return nil // already enabled
	}
	if info.Text != "" {
		fmt.Fprintln(Stdout, "\n"+info.Text)
	}
	if info.URL != "" {
		fmt.Fprintln(Stdout, "\n         "+info.URL+"\n")
	}
	if !info.ShouldWait {
		e.lc.IncrementCounter(ctx, fmt.Sprintf("%s_not_awaiting_enablement", feature), 1)
		// The feature has not been enabled yet,
		// but the CLI should not block on user action.
		// Once info.Text is printed, exit the CLI.
		os.Exit(0)
	}
	e.lc.IncrementCounter(ctx, fmt.Sprintf("%s_awaiting_enablement", feature), 1)
	// Block until feature is enabled.
	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	watcher, err := e.lc.WatchIPNBus(watchCtx, 0)
	if err != nil {
		// If we fail to connect to the IPN notification bus,
		// don't block. We still present the URL in the CLI,
		// then close the process. Swallow the error.
		log.Fatalf("lost connection to tailscaled: %v", err)
		e.lc.IncrementCounter(ctx, fmt.Sprintf("%s_enablement_lost_connection", feature), 1)
		return err
	}
	defer watcher.Close()
	for {
		n, err := watcher.Next()
		if err != nil {
			// Stop blocking if we error.
			// Let the user finish enablement then rerun their
			// command themselves.
			log.Fatalf("lost connection to tailscaled: %v", err)
			e.lc.IncrementCounter(ctx, fmt.Sprintf("%s_enablement_lost_connection", feature), 1)
			return err
		}
		if nm := n.NetMap; nm != nil && nm.SelfNode.Valid() {
			gotAll := true
			for _, c := range caps {
				if !nm.SelfNode.HasCap(c) {
					// The feature is not yet enabled.
					// Continue blocking until it is.
					gotAll = false
					break
				}
			}
			if gotAll {
				e.lc.IncrementCounter(ctx, fmt.Sprintf("%s_enabled", feature), 1)
				fmt.Fprintln(Stdout, "Success.")
				return nil
			}
		}
	}
}
