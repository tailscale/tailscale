// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/version"
)

type execFunc func(ctx context.Context, args []string) error

type commandInfo struct {
	Name      string
	ShortHelp string
	LongHelp  string
}

var serveHelpCommon = strings.TrimSpace(`
<target> can be a port number (e.g., 3000), a partial URL (e.g., localhost:3000), or a
full URL including a path (e.g., http://localhost:3000/foo, https+insecure://localhost:3000/foo).

EXAMPLES
  - Mount a local web server at 127.0.0.1:3000 in the foreground:
    $ tailscale %s localhost:3000

  - Mount a local web server at 127.0.0.1:3000 in the background:
    $ tailscale %s --bg localhost:3000

For more examples and use cases visit our docs site https://tailscale.com/kb/1247/funnel-serve-use-cases
`)

type serveMode int

const (
	serve serveMode = iota
	funnel
)

var infoMap = map[serveMode]commandInfo{
	serve: {
		Name:      "serve",
		ShortHelp: "Serve content and local servers on your tailnet",
		LongHelp: strings.Join([]string{
			"Serve enables you to share a local server securely within your tailnet.\n",
			"To share a local server on the internet, use `tailscale funnel`\n\n",
		}, "\n"),
	},
	funnel: {
		Name:      "funnel",
		ShortHelp: "Serve content and local servers on the internet",
		LongHelp: strings.Join([]string{
			"Funnel enables you to share a local server on the internet using Tailscale.\n",
			"To share only within your tailnet, use `tailscale serve`\n\n",
		}, "\n"),
	},
}

func buildShortUsage(subcmd string) string {
	return strings.Join([]string{
		subcmd + " [flags] <target> [off]",
		subcmd + " status [--json]",
		subcmd + " reset",
	}, "\n  ")
}

// newServeDevCommand returns a new "serve" subcommand using e as its environment.
func newServeDevCommand(e *serveEnv, subcmd serveMode) *ffcli.Command {
	if subcmd != serve && subcmd != funnel {
		log.Fatalf("newServeDevCommand called with unknown subcmd %q", subcmd)
	}

	info := infoMap[subcmd]

	return &ffcli.Command{
		Name:      info.Name,
		ShortHelp: info.ShortHelp,
		ShortUsage: strings.Join([]string{
			fmt.Sprintf("%s <target>", info.Name),
			fmt.Sprintf("%s status [--json]", info.Name),
			fmt.Sprintf("%s reset", info.Name),
		}, "\n  "),
		LongHelp: info.LongHelp + fmt.Sprintf(strings.TrimSpace(serveHelpCommon), subcmd, subcmd),
		Exec:     e.runServeCombined(subcmd),

		FlagSet: e.newFlags("serve-set", func(fs *flag.FlagSet) {
			fs.BoolVar(&e.bg, "bg", false, "run the command in the background")
			fs.StringVar(&e.setPath, "set-path", "", "set a path for a specific target and run in the background")
			fs.StringVar(&e.https, "https", "", "default; HTTPS listener")
			fs.StringVar(&e.http, "http", "", "HTTP listener")
			fs.StringVar(&e.tcp, "tcp", "", "TCP listener")
			fs.StringVar(&e.tlsTerminatedTcp, "tls-terminated-tcp", "", "TLS terminated TCP listener")

		}),
		UsageFunc: usageFunc,
		Subcommands: []*ffcli.Command{
			{
				Name:      "status",
				Exec:      e.runServeStatus,
				ShortHelp: "view current proxy configuration",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
				UsageFunc: usageFunc,
			},
			{
				Name:      "reset",
				ShortHelp: "reset current serve/funnel config",
				Exec:      e.runServeReset,
				FlagSet:   e.newFlags("serve-reset", nil),
				UsageFunc: usageFunc,
			},
		},
	}
}

// runServeCombined is the entry point for the "tailscale {serve,funnel}" commands.
func (e *serveEnv) runServeCombined(subcmd serveMode) execFunc {
	e.subcmd = subcmd

	return func(ctx context.Context, args []string) error {
		if len(args) == 0 {
			return flag.ErrHelp
		}

		funnel := subcmd == funnel

		err := checkLegacyServeInvocation(subcmd, args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: the CLI for serve and funnel has changed.\n")
			fmt.Fprintf(os.Stderr, "Please see https://tailscale.com/kb/1242/tailscale-serve for more information.\n\n")

			return errHelp
		}

		if len(args) > 2 {
			fmt.Fprintf(os.Stderr, "error: invalid number of arguments (%d)\n\n", len(args))
			return errHelp
		}

		turnOff := "off" == args[len(args)-1]

		// support passing in a port number as the target
		// TODO(tylersmalley) move to expandProxyTarget when we remove the legacy serve invocation
		target := args[0]
		port, err := strconv.ParseUint(args[0], 10, 16)
		if err == nil {
			target = fmt.Sprintf("http://127.0.0.1:%d", port)
		}

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		st, err := e.getLocalClientStatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("getting client status: %w", err)
		}

		if funnel {
			// verify node has funnel capabilities
			if err := e.verifyFunnelEnabled(ctx, st, 443); err != nil {
				return err
			}
		}

		// default mount point to "/"
		mount := e.setPath
		if mount == "" {
			mount = "/"
		}

		if e.bg || turnOff || e.setPath != "" {
			srvType, srvPort, err := srvTypeAndPortFromFlags(e)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
				return errHelp
			}

			if turnOff {
				err := e.unsetServe(ctx, srvType, srvPort, mount)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
					return errHelp
				}
				return nil
			}

			err = e.setServe(ctx, st, srvType, srvPort, mount, target, funnel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
				return errHelp
			}

			return nil
		}

		dnsName := strings.TrimSuffix(st.Self.DNSName, ".")
		hp := ipn.HostPort(dnsName + ":443") // TODO(marwan-at-work): support the 2 other ports

		// TODO(marwan-at-work): combine this with the above setServe code.
		// Foreground and background should be the same, we just pass
		// a foreground config instead of the top level background one.
		return e.streamServe(ctx, ipn.ServeStreamRequest{
			Funnel:     funnel,
			HostPort:   hp,
			Source:     target,
			MountPoint: mount,
		})
	}
}

func (e *serveEnv) streamServe(ctx context.Context, req ipn.ServeStreamRequest) error {
	watcher, err := e.lc.WatchIPNBus(ctx, ipn.NotifyInitialState)
	if err != nil {
		return err
	}
	defer watcher.Close()
	n, err := watcher.Next()
	if err != nil {
		return err
	}
	sessionID := n.SessionID
	if sessionID == "" {
		return errors.New("missing SessionID")
	}
	sc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return fmt.Errorf("error getting serve config: %w", err)
	}
	if sc == nil {
		sc = &ipn.ServeConfig{}
	}
	setHandler(sc, req, sessionID)
	err = e.lc.SetServeConfig(ctx, sc)
	if err != nil {
		return fmt.Errorf("error setting serve config: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Funnel started on \"https://%s\".\n", strings.TrimSuffix(string(req.HostPort), ":443"))
	fmt.Fprintf(os.Stderr, "Press Ctrl-C to stop Funnel.\n\n")

	for {
		_, err = watcher.Next()
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
}

// setHandler modifies sc to add a Foreground config (described by req) with the given sessionID.
func setHandler(sc *ipn.ServeConfig, req ipn.ServeStreamRequest, sessionID string) {
	fconf := &ipn.ServeConfig{}
	mak.Set(&sc.Foreground, sessionID, fconf)
	mak.Set(&fconf.TCP, 443, &ipn.TCPPortHandler{HTTPS: true})

	wsc := &ipn.WebServerConfig{}
	mak.Set(&fconf.Web, req.HostPort, wsc)
	mak.Set(&wsc.Handlers, req.MountPoint, &ipn.HTTPHandler{
		Proxy: req.Source,
	})
	mak.Set(&fconf.AllowFunnel, req.HostPort, true)
}

func (e *serveEnv) setServe(ctx context.Context, st *ipnstate.Status, srvType string, srvPort uint16, mount string, target string, allowFunnel bool) error {
	if srvType == "https" {
		// Running serve with https requires that the tailnet has enabled
		// https cert provisioning. Send users through an interactive flow
		// to enable this if not already done.
		//
		// TODO(sonia,tailscale/corp#10577): The interactive feature flow
		// is behind a control flag. If the tailnet doesn't have the flag
		// on, enableFeatureInteractive will error. For now, we hide that
		// error and maintain the previous behavior (prior to 2023-08-15)
		// of letting them edit the serve config before enabling certs.
		e.enableFeatureInteractive(ctx, "serve", func(caps []string) bool {
			return slices.Contains(caps, tailcfg.CapabilityHTTPS)
		})
	}

	// get serve config
	sc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}

	dnsName, err := e.getSelfDNSName(ctx)
	if err != nil {
		return err
	}

	// nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	// update serve config based on the type
	switch srvType {
	case "https", "http":
		mount, err := cleanMountPoint(mount)
		if err != nil {
			return fmt.Errorf("failed to clean the mount point: %w", err)
		}
		useTLS := srvType == "https"
		err = e.applyWebServe(sc, dnsName, srvPort, useTLS, mount, target)
		if err != nil {
			return fmt.Errorf("failed apply web serve: %w", err)
		}
	case "tcp", "tls-terminated-tcp":
		err = e.applyTCPServe(sc, dnsName, srvType, srvPort, target)
		if err != nil {
			return fmt.Errorf("failed to apply TCP serve: %w", err)
		}
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}

	// update the serve config based on if funnel is enabled
	e.applyFunnel(sc, dnsName, srvPort, allowFunnel)

	// persist the serve config changes
	if err := e.lc.SetServeConfig(ctx, sc); err != nil {
		return err
	}

	// notify the user of the change
	m, err := e.messageForPort(ctx, sc, st, dnsName, srvPort)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, m)

	return nil
}

func (e *serveEnv) messageForPort(ctx context.Context, sc *ipn.ServeConfig, st *ipnstate.Status, dnsName string, srvPort uint16) (string, error) {
	var output strings.Builder

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	if sc.AllowFunnel[hp] == true {
		output.WriteString("Available on the internet:\n")
	} else {
		output.WriteString("Available within your tailnet:\n")
	}

	scheme := "https"
	if sc.IsServingHTTP(srvPort) {
		scheme = "http"
	}

	portPart := ":" + fmt.Sprint(srvPort)
	if scheme == "http" && srvPort == 80 ||
		scheme == "https" && srvPort == 443 {
		portPart = ""
	}

	output.WriteString(fmt.Sprintf("%s://%s%s\n\n", scheme, dnsName, portPart))

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

	if sc.Web[hp] != nil {
		var mounts []string

		for k := range sc.Web[hp].Handlers {
			mounts = append(mounts, k)
		}
		sort.Slice(mounts, func(i, j int) bool {
			return len(mounts[i]) < len(mounts[j])
		})
		maxLen := len(mounts[len(mounts)-1])

		for _, m := range mounts {
			h := sc.Web[hp].Handlers[m]
			t, d := srvTypeAndDesc(h)
			output.WriteString(fmt.Sprintf("%s %s%s %-5s %s\n", "|--", m, strings.Repeat(" ", maxLen-len(m)), t, d))
		}
	} else if sc.TCP[srvPort] != nil {
		h := sc.TCP[srvPort]

		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}

		output.WriteString(fmt.Sprintf("|-- tcp://%s (%s)\n", hp, tlsStatus))
		for _, a := range st.TailscaleIPs {
			ipp := net.JoinHostPort(a.String(), strconv.Itoa(int(srvPort)))
			output.WriteString(fmt.Sprintf("|-- tcp://%s\n", ipp))
		}
		output.WriteString(fmt.Sprintf("|--> tcp://%s\n", h.TCPForward))
	}

	output.WriteString("\nServe started and running in the background.\n")
	output.WriteString(fmt.Sprintf("To disable the proxy, run: tailscale %s off", infoMap[e.subcmd].Name))

	return output.String(), nil
}

func (e *serveEnv) applyWebServe(sc *ipn.ServeConfig, dnsName string, srvPort uint16, useTLS bool, mount, target string) error {
	h := new(ipn.HTTPHandler)

	// TODO: use strings.Cut as the prefix OR use strings.HasPrefix
	ts, _, _ := strings.Cut(target, ":")
	switch {
	case ts == "text":
		text := strings.TrimPrefix(target, "text:")
		if text == "" {
			return errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = text
	case isProxyTarget(target):
		t, err := expandProxyTarget(target)
		if err != nil {
			return err
		}
		h.Proxy = t
	default: // assume path
		if version.IsSandboxedMacOS() {
			// don't allow path serving for now on macOS (2022-11-15)
			return errors.New("path serving is not supported if sandboxed on macOS")
		}
		if !filepath.IsAbs(target) {
			return errors.New("path must be absolute")
		}
		target = filepath.Clean(target)
		fi, err := os.Stat(target)
		if err != nil {
			return errors.New("invalid path")
		}

		// TODO: need to understand this further
		if fi.IsDir() && !strings.HasSuffix(mount, "/") {
			// dir mount points must end in /
			// for relative file links to work
			mount += "/"
		}
		h.Path = target
	}

	// TODO: validation needs to check nested foreground configs
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot serve web; already serving TCP")
	}

	mak.Set(&sc.TCP, srvPort, &ipn.TCPPortHandler{HTTPS: useTLS, HTTP: !useTLS})

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))
	if _, ok := sc.Web[hp]; !ok {
		mak.Set(&sc.Web, hp, new(ipn.WebServerConfig))
	}
	mak.Set(&sc.Web[hp].Handlers, mount, h)

	// TODO: handle multiple web handlers from foreground mode
	for k, v := range sc.Web[hp].Handlers {
		if v == h {
			continue
		}
		// If the new mount point ends in / and another mount point
		// shares the same prefix, remove the other handler.
		// (e.g. /foo/ overwrites /foo)
		// The opposite example is also handled.
		m1 := strings.TrimSuffix(mount, "/")
		m2 := strings.TrimSuffix(k, "/")
		if m1 == m2 {
			delete(sc.Web[hp].Handlers, k)
		}
	}

	return nil
}

func (e *serveEnv) applyTCPServe(sc *ipn.ServeConfig, dnsName string, srcType string, srcPort uint16, target string) error {
	var terminateTLS bool
	switch srcType {
	case "tcp":
		terminateTLS = false
	case "tls-terminated-tcp":
		terminateTLS = true
	default:
		return fmt.Errorf("invalid TCP target %q", target)
	}

	dstURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid TCP target %q: %v", target, err)
	}
	host, dstPortStr, err := net.SplitHostPort(dstURL.Host)
	if err != nil {
		return fmt.Errorf("invalid TCP target %q: %v", target, err)
	}

	switch host {
	case "localhost", "127.0.0.1":
		// ok
	default:
		return fmt.Errorf("invalid TCP target %q, must be one of localhost or 127.0.0.1", target)
	}

	if p, err := strconv.ParseUint(dstPortStr, 10, 16); p == 0 || err != nil {
		return fmt.Errorf("invalid port %q", dstPortStr)
	}

	fwdAddr := "127.0.0.1:" + dstPortStr

	// TODO: needs to account for multiple configs from foreground mode
	if sc.IsServingWeb(srcPort) {
		return fmt.Errorf("cannot serve TCP; already serving web on %d", srcPort)
	}

	mak.Set(&sc.TCP, srcPort, &ipn.TCPPortHandler{TCPForward: fwdAddr})

	if terminateTLS {
		sc.TCP[srcPort].TerminateTLS = dnsName
	}

	return nil
}

func (e *serveEnv) applyFunnel(sc *ipn.ServeConfig, dnsName string, srvPort uint16, allowFunnel bool) {
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	// TODO: Should we return an error? Should not be possible.
	// nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	// TODO: should ensure there is no other conflicting funnel
	// TODO: add error handling for if toggling for existing sc
	if allowFunnel {
		mak.Set(&sc.AllowFunnel, hp, true)
	}
}

// TODO(tylersmalley) Refactor into setServe so handleWebServeFunnelRemove and handleTCPServeRemove.
// apply serve config changes and we print a status message.
func (e *serveEnv) unsetServe(ctx context.Context, srvType string, srvPort uint16, mount string) error {
	switch srvType {
	case "https", "http":
		mount, err := cleanMountPoint(mount)
		if err != nil {
			return fmt.Errorf("failed to clean the mount point: %w", err)
		}
		err = e.handleWebServeFunnelRemove(ctx, srvPort, mount)
		if err != nil {
			return err
		}

		return nil
	case "tcp", "tls-terminated-tcp":
		// TODO(tylersmalley) should remove funnel
		return e.removeTCPServe(ctx, srvPort)
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}
}

func srvTypeAndPortFromFlags(e *serveEnv) (srvType string, srvPort uint16, err error) {
	sourceMap := map[string]string{
		"http":               e.http,
		"https":              e.https,
		"tcp":                e.tcp,
		"tls-terminated-tcp": e.tlsTerminatedTcp,
	}

	var srcTypeCount int
	var srcValue string

	for k, v := range sourceMap {
		if v != "" {
			srcTypeCount++
			srvType = k
			srcValue = v
		}
	}

	if srcTypeCount > 1 {
		return "", 0, fmt.Errorf("cannot serve multiple types for a single mount point")
	} else if srcTypeCount == 0 {
		srvType = "https"
		srcValue = "443"
	}

	srvPort, err = parseServePort(srcValue)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", srcValue, err)
	}

	return srvType, srvPort, nil
}

func checkLegacyServeInvocation(subcmd serveMode, args []string) error {
	if subcmd == serve && len(args) == 2 {
		prefixes := []string{"http:", "https:", "tls:", "tls-terminated-tcp:"}

		for _, prefix := range prefixes {
			if strings.HasPrefix(args[0], prefix) {
				return errors.New("invalid invocation")
			}
		}
	}

	return nil
}

// handleWebServeFunnelRemove removes a web handler from the serve config
// and removes funnel if no remaining mounts exist for the serve port.
// The srvPort argument is the serving port and the mount argument is
// the mount point or registered path to remove.
// TODO(tylersmalley): fork of handleWebServeRemove, return name once dev work is merged
func (e *serveEnv) handleWebServeFunnelRemove(ctx context.Context, srvPort uint16, mount string) error {
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
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot remove web handler; currently serving TCP")
	}
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))
	if !sc.WebHandlerExists(hp, mount) {
		return errors.New("error: handler does not exist")
	}
	// delete existing handler, then cascade delete if empty
	delete(sc.Web[hp].Handlers, mount)
	if len(sc.Web[hp].Handlers) == 0 {
		delete(sc.Web, hp)
		delete(sc.TCP, srvPort)
	}
	// clear empty maps mostly for testing
	if len(sc.Web) == 0 {
		sc.Web = nil
	}
	if len(sc.TCP) == 0 {
		sc.TCP = nil
	}

	// disable funnel if no remaining mounts exist for the serve port
	if sc.Web == nil && sc.TCP == nil {
		delete(sc.AllowFunnel, hp)
	}

	if err := e.lc.SetServeConfig(ctx, sc); err != nil {
		return err
	}

	return nil
}

// removeTCPServe removes the TCP forwarding configuration for the
// given srvPort, or serving port.
func (e *serveEnv) removeTCPServe(ctx context.Context, src uint16) error {
	cursc, err := e.lc.GetServeConfig(ctx)
	if err != nil {
		return err
	}
	sc := cursc.Clone() // nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}
	if sc.IsServingWeb(src) {
		return fmt.Errorf("unable to remove; serving web, not TCP forwarding on serve port %d", src)
	}
	if ph := sc.GetTCPPortHandler(src); ph != nil {
		delete(sc.TCP, src)
		// clear map mostly for testing
		if len(sc.TCP) == 0 {
			sc.TCP = nil
		}
		return e.lc.SetServeConfig(ctx, sc)
	}
	return errors.New("error: serve config does not exist")
}
