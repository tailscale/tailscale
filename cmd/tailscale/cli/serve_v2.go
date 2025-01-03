// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/util/slicesx"
	"tailscale.com/version"
)

type execFunc func(ctx context.Context, args []string) error

type commandInfo struct {
	Name      string
	ShortHelp string
	LongHelp  string
}

var serveHelpCommon = strings.TrimSpace(`
<target> can be a file, directory, text, or most commonly the location to a service running on the
local machine. The location to the location service can be expressed as a port number (e.g., 3000),
a partial URL (e.g., localhost:3000), or a full URL including a path (e.g., http://localhost:3000/foo).

EXAMPLES
  - Expose an HTTP server running at 127.0.0.1:3000 in the foreground:
    $ tailscale %[1]s 3000

  - Expose an HTTP server running at 127.0.0.1:3000 in the background:
    $ tailscale %[1]s --bg 3000

  - Expose an HTTPS server with invalid or self-signed certificates at https://localhost:8443
    $ tailscale %[1]s https+insecure://localhost:8443

For more examples and use cases visit our docs site https://tailscale.com/kb/1247/funnel-serve-use-cases
`)

type serveMode int

const (
	serve serveMode = iota
	funnel
)

type serveType int

const (
	serveTypeHTTPS serveType = iota
	serveTypeHTTP
	serveTypeTCP
	serveTypeTLSTerminatedTCP
)

var infoMap = map[serveMode]commandInfo{
	serve: {
		Name:      "serve",
		ShortHelp: "Serve content and local servers on your tailnet",
		LongHelp: strings.Join([]string{
			"Tailscale Serve enables you to share a local server securely within your tailnet.\n",
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

// errHelpFunc is standard error text that prompts users to
// run `$subcmd --help` for information on how to use serve.
var errHelpFunc = func(m serveMode) error {
	return fmt.Errorf("try `tailscale %s --help` for usage info", infoMap[m].Name)
}

// newServeV2Command returns a new "serve" subcommand using e as its environment.
func newServeV2Command(e *serveEnv, subcmd serveMode) *ffcli.Command {
	if subcmd != serve && subcmd != funnel {
		log.Fatalf("newServeDevCommand called with unknown subcmd %q", subcmd)
	}

	info := infoMap[subcmd]

	return &ffcli.Command{
		Name:      info.Name,
		ShortHelp: info.ShortHelp,
		ShortUsage: strings.Join([]string{
			fmt.Sprintf("tailscale %s <target>", info.Name),
			fmt.Sprintf("tailscale %s status [--json]", info.Name),
			fmt.Sprintf("tailscale %s reset", info.Name),
		}, "\n"),
		LongHelp: info.LongHelp + fmt.Sprintf(strings.TrimSpace(serveHelpCommon), info.Name),
		Exec:     e.runServeCombined(subcmd),

		FlagSet: e.newFlags("serve-set", func(fs *flag.FlagSet) {
			fs.BoolVar(&e.bg, "bg", false, "Run the command as a background process (default false)")
			fs.StringVar(&e.setPath, "set-path", "", "Appends the specified path to the base URL for accessing the underlying service")
			fs.UintVar(&e.https, "https", 0, "Expose an HTTPS server at the specified port (default mode)")
			if subcmd == serve {
				fs.UintVar(&e.http, "http", 0, "Expose an HTTP server at the specified port")
			}
			fs.UintVar(&e.tcp, "tcp", 0, "Expose a TCP forwarder to forward raw TCP packets at the specified port")
			fs.UintVar(&e.tlsTerminatedTCP, "tls-terminated-tcp", 0, "Expose a TCP forwarder to forward TLS-terminated TCP packets at the specified port")
			fs.BoolVar(&e.yes, "yes", false, "Update without interactive prompts (default false)")
		}),
		UsageFunc: usageFuncNoDefaultValues,
		Subcommands: []*ffcli.Command{
			{
				Name:       "status",
				ShortUsage: "tailscale " + info.Name + " status [--json]",
				Exec:       e.runServeStatus,
				ShortHelp:  "View current " + info.Name + " configuration",
				FlagSet: e.newFlags("serve-status", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.json, "json", false, "output JSON")
				}),
			},
			{
				Name:       "reset",
				ShortUsage: "tailscale " + info.Name + " reset",
				ShortHelp:  "Reset current " + info.Name + " config",
				Exec:       e.runServeReset,
				FlagSet:    e.newFlags("serve-reset", nil),
			},
		},
	}
}

func (e *serveEnv) validateArgs(subcmd serveMode, args []string) error {
	if translation, ok := isLegacyInvocation(subcmd, args); ok {
		fmt.Fprint(e.stderr(), "Error: the CLI for serve and funnel has changed.")
		if translation != "" {
			fmt.Fprint(e.stderr(), " You can run the following command instead:\n")
			fmt.Fprintf(e.stderr(), "\t- %s\n", translation)
		}
		fmt.Fprint(e.stderr(), "\nPlease see https://tailscale.com/kb/1242/tailscale-serve for more information.\n")
		return errHelpFunc(subcmd)
	}
	if len(args) == 0 {
		return flag.ErrHelp
	}
	if len(args) > 2 {
		fmt.Fprintf(e.stderr(), "Error: invalid number of arguments (%d)\n", len(args))
		return errHelpFunc(subcmd)
	}
	turnOff := args[len(args)-1] == "off"
	if len(args) == 2 && !turnOff {
		fmt.Fprintln(e.stderr(), "Error: invalid argument format")
		return errHelpFunc(subcmd)
	}

	// Given the two checks above, we can assume there
	// are only 1 or 2 arguments which is valid.
	return nil
}

// runServeCombined is the entry point for the "tailscale {serve,funnel}" commands.
func (e *serveEnv) runServeCombined(subcmd serveMode) execFunc {
	e.subcmd = subcmd

	return func(ctx context.Context, args []string) error {
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

		if err := e.validateArgs(subcmd, args); err != nil {
			return err
		}

		ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
		defer cancel()

		funnel := subcmd == funnel
		if funnel {
			// verify node has funnel capabilities
			if err := e.verifyFunnelEnabled(ctx, 443); err != nil {
				return err
			}
		}

		mount, err := cleanURLPath(e.setPath)
		if err != nil {
			return fmt.Errorf("failed to clean the mount point: %w", err)
		}

		srvType, srvPort, err := srvTypeAndPortFromFlags(e)
		if err != nil {
			fmt.Fprintf(e.stderr(), "error: %v\n\n", err)
			return errHelpFunc(subcmd)
		}

		sc, err := e.lc.GetServeConfig(ctx)
		if err != nil {
			return fmt.Errorf("error getting serve config: %w", err)
		}

		// nil if no config
		if sc == nil {
			sc = new(ipn.ServeConfig)
		}
		st, err := e.getLocalClientStatusWithoutPeers(ctx)
		if err != nil {
			return fmt.Errorf("getting client status: %w", err)
		}
		dnsName := strings.TrimSuffix(st.Self.DNSName, ".")

		// set parent serve config to always be persisted
		// at the top level, but a nested config might be
		// the one that gets manipulated depending on
		// foreground or background.
		parentSC := sc

		turnOff := "off" == args[len(args)-1]
		if !turnOff && srvType == serveTypeHTTPS {
			// Running serve with https requires that the tailnet has enabled
			// https cert provisioning. Send users through an interactive flow
			// to enable this if not already done.
			//
			// TODO(sonia,tailscale/corp#10577): The interactive feature flow
			// is behind a control flag. If the tailnet doesn't have the flag
			// on, enableFeatureInteractive will error. For now, we hide that
			// error and maintain the previous behavior (prior to 2023-08-15)
			// of letting them edit the serve config before enabling certs.
			if err := e.enableFeatureInteractive(ctx, "serve", tailcfg.CapabilityHTTPS); err != nil {
				return fmt.Errorf("error enabling https feature: %w", err)
			}
		}

		var watcher *tailscale.IPNBusWatcher
		wantFg := !e.bg && !turnOff
		if wantFg {
			// validate the config before creating a WatchIPNBus session
			if err := e.validateConfig(parentSC, srvPort, srvType); err != nil {
				return err
			}

			// if foreground mode, create a WatchIPNBus session
			// and use the nested config for all following operations
			// TODO(marwan-at-work): nested-config validations should happen here or previous to this point.
			watcher, err = e.lc.WatchIPNBus(ctx, ipn.NotifyInitialState|ipn.NotifyNoPrivateKeys)
			if err != nil {
				return err
			}
			defer watcher.Close()
			n, err := watcher.Next()
			if err != nil {
				return err
			}
			if n.SessionID == "" {
				return errors.New("missing SessionID")
			}
			fsc := &ipn.ServeConfig{}
			mak.Set(&sc.Foreground, n.SessionID, fsc)
			sc = fsc
		}

		var msg string
		if turnOff {
			err = e.unsetServe(sc, dnsName, srvType, srvPort, mount)
		} else {
			if err := e.validateConfig(parentSC, srvPort, srvType); err != nil {
				return err
			}
			err = e.setServe(sc, st, dnsName, srvType, srvPort, mount, args[0], funnel)
			msg = e.messageForPort(sc, st, dnsName, srvType, srvPort)
		}
		if err != nil {
			fmt.Fprintf(e.stderr(), "error: %v\n\n", err)
			return errHelpFunc(subcmd)
		}

		if err := e.lc.SetServeConfig(ctx, parentSC); err != nil {
			if tailscale.IsPreconditionsFailedError(err) {
				fmt.Fprintln(e.stderr(), "Another client is changing the serve config; please try again.")
			}
			return err
		}

		if msg != "" {
			fmt.Fprintln(e.stdout(), msg)
		}

		if watcher != nil {
			for {
				_, err = watcher.Next()
				if err != nil {
					if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
						return nil
					}
					return err
				}
			}
		}

		return nil
	}
}

const backgroundExistsMsg = "background configuration already exists, use `tailscale %s --%s=%d off` to remove the existing configuration"

func (e *serveEnv) validateConfig(sc *ipn.ServeConfig, port uint16, wantServe serveType) error {
	sc, isFg := sc.FindConfig(port)
	if sc == nil {
		return nil
	}
	if isFg {
		return errors.New("foreground already exists under this port")
	}
	if !e.bg {
		return fmt.Errorf(backgroundExistsMsg, infoMap[e.subcmd].Name, wantServe.String(), port)
	}
	existingServe := serveFromPortHandler(sc.TCP[port])
	if wantServe != existingServe {
		return fmt.Errorf("want %q but port is already serving %q", wantServe, existingServe)
	}
	return nil
}

func serveFromPortHandler(tcp *ipn.TCPPortHandler) serveType {
	switch {
	case tcp.HTTP:
		return serveTypeHTTP
	case tcp.HTTPS:
		return serveTypeHTTPS
	case tcp.TerminateTLS != "":
		return serveTypeTLSTerminatedTCP
	case tcp.TCPForward != "":
		return serveTypeTCP
	default:
		return -1
	}
}

func (e *serveEnv) setServe(sc *ipn.ServeConfig, st *ipnstate.Status, dnsName string, srvType serveType, srvPort uint16, mount string, target string, allowFunnel bool) error {
	// update serve config based on the type
	switch srvType {
	case serveTypeHTTPS, serveTypeHTTP:
		useTLS := srvType == serveTypeHTTPS
		err := e.applyWebServe(sc, dnsName, srvPort, useTLS, mount, target)
		if err != nil {
			return fmt.Errorf("failed apply web serve: %w", err)
		}
	case serveTypeTCP, serveTypeTLSTerminatedTCP:
		if e.setPath != "" {
			return fmt.Errorf("cannot mount a path for TCP serve")
		}

		err := e.applyTCPServe(sc, dnsName, srvType, srvPort, target)
		if err != nil {
			return fmt.Errorf("failed to apply TCP serve: %w", err)
		}
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}

	// update the serve config based on if funnel is enabled
	e.applyFunnel(sc, dnsName, srvPort, allowFunnel)

	return nil
}

var (
	msgFunnelAvailable     = "Available on the internet:"
	msgServeAvailable      = "Available within your tailnet:"
	msgRunningInBackground = "%s started and running in the background."
	msgDisableProxy        = "To disable the proxy, run: tailscale %s --%s=%d off"
	msgToExit              = "Press Ctrl+C to exit."
)

// messageForPort returns a message for the given port based on the
// serve config and status.
func (e *serveEnv) messageForPort(sc *ipn.ServeConfig, st *ipnstate.Status, dnsName string, srvType serveType, srvPort uint16) string {
	var output strings.Builder

	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	if sc.AllowFunnel[hp] == true {
		output.WriteString(msgFunnelAvailable)
	} else {
		output.WriteString(msgServeAvailable)
	}
	output.WriteString("\n\n")

	scheme := "https"
	if sc.IsServingHTTP(srvPort) {
		scheme = "http"
	}

	portPart := ":" + fmt.Sprint(srvPort)
	if scheme == "http" && srvPort == 80 ||
		scheme == "https" && srvPort == 443 {
		portPart = ""
	}

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
		mounts := slicesx.MapKeys(sc.Web[hp].Handlers)
		sort.Slice(mounts, func(i, j int) bool {
			return len(mounts[i]) < len(mounts[j])
		})

		for _, m := range mounts {
			h := sc.Web[hp].Handlers[m]
			t, d := srvTypeAndDesc(h)
			output.WriteString(fmt.Sprintf("%s://%s%s%s\n", scheme, dnsName, portPart, m))
			output.WriteString(fmt.Sprintf("%s %-5s %s\n\n", "|--", t, d))
		}
	} else if sc.TCP[srvPort] != nil {
		h := sc.TCP[srvPort]

		tlsStatus := "TLS over TCP"
		if h.TerminateTLS != "" {
			tlsStatus = "TLS terminated"
		}

		output.WriteString(fmt.Sprintf("%s://%s%s\n", scheme, dnsName, portPart))
		output.WriteString(fmt.Sprintf("|-- tcp://%s (%s)\n", hp, tlsStatus))
		for _, a := range st.TailscaleIPs {
			ipp := net.JoinHostPort(a.String(), strconv.Itoa(int(srvPort)))
			output.WriteString(fmt.Sprintf("|-- tcp://%s\n", ipp))
		}
		output.WriteString(fmt.Sprintf("|--> tcp://%s\n", h.TCPForward))
	}

	if !e.bg {
		output.WriteString(msgToExit)
		return output.String()
	}

	subCmd := infoMap[e.subcmd].Name
	subCmdUpper := strings.ToUpper(string(subCmd[0])) + subCmd[1:]

	output.WriteString(fmt.Sprintf(msgRunningInBackground, subCmdUpper))
	output.WriteString("\n")
	output.WriteString(fmt.Sprintf(msgDisableProxy, subCmd, srvType.String(), srvPort))

	return output.String()
}

func (e *serveEnv) applyWebServe(sc *ipn.ServeConfig, dnsName string, srvPort uint16, useTLS bool, mount, target string) error {
	h := new(ipn.HTTPHandler)

	switch {
	case strings.HasPrefix(target, "text:"):
		text := strings.TrimPrefix(target, "text:")
		if text == "" {
			return errors.New("unable to serve; text cannot be an empty string")
		}
		h.Text = text
	case filepath.IsAbs(target):
		if version.IsMacAppStore() || version.IsMacSys() {
			// The Tailscale network extension cannot serve arbitrary paths on macOS due to sandbox restrictions (2024-03-26)
			return errors.New("Path serving is not supported on macOS due to sandbox restrictions. To use Tailscale Serve on macOS, switch to the open-source tailscaled distribution. See https://tailscale.com/kb/1065/macos-variants for more information.")
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
	default:
		t, err := ipn.ExpandProxyTargetValue(target, []string{"http", "https", "https+insecure"}, "http")
		if err != nil {
			return err
		}
		h.Proxy = t
	}

	// TODO: validation needs to check nested foreground configs
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot serve web; already serving TCP")
	}

	sc.SetWebHandler(h, dnsName, srvPort, mount, useTLS)

	return nil
}

func (e *serveEnv) applyTCPServe(sc *ipn.ServeConfig, dnsName string, srcType serveType, srcPort uint16, target string) error {
	var terminateTLS bool
	switch srcType {
	case serveTypeTCP:
		terminateTLS = false
	case serveTypeTLSTerminatedTCP:
		terminateTLS = true
	default:
		return fmt.Errorf("invalid TCP target %q", target)
	}

	targetURL, err := ipn.ExpandProxyTargetValue(target, []string{"tcp"}, "tcp")
	if err != nil {
		return fmt.Errorf("unable to expand target: %v", err)
	}

	dstURL, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid TCP target %q: %v", target, err)
	}

	// TODO: needs to account for multiple configs from foreground mode
	if sc.IsServingWeb(srcPort) {
		return fmt.Errorf("cannot serve TCP; already serving web on %d", srcPort)
	}

	sc.SetTCPForwarding(srcPort, dstURL.Host, terminateTLS, dnsName)

	return nil
}

func (e *serveEnv) applyFunnel(sc *ipn.ServeConfig, dnsName string, srvPort uint16, allowFunnel bool) {
	hp := ipn.HostPort(net.JoinHostPort(dnsName, strconv.Itoa(int(srvPort))))

	// TODO: Should we return an error? Should not be possible.
	// nil if no config
	if sc == nil {
		sc = new(ipn.ServeConfig)
	}

	if _, exists := sc.AllowFunnel[hp]; exists && !allowFunnel {
		fmt.Fprintf(e.stderr(), "Removing Funnel for %s:%s\n", dnsName, hp)
	}
	sc.SetFunnel(dnsName, srvPort, allowFunnel)
}

// unsetServe removes the serve config for the given serve port.
func (e *serveEnv) unsetServe(sc *ipn.ServeConfig, dnsName string, srvType serveType, srvPort uint16, mount string) error {
	switch srvType {
	case serveTypeHTTPS, serveTypeHTTP:
		err := e.removeWebServe(sc, dnsName, srvPort, mount)
		if err != nil {
			return fmt.Errorf("failed to remove web serve: %w", err)
		}
	case serveTypeTCP, serveTypeTLSTerminatedTCP:
		err := e.removeTCPServe(sc, srvPort)
		if err != nil {
			return fmt.Errorf("failed to remove TCP serve: %w", err)
		}
	default:
		return fmt.Errorf("invalid type %q", srvType)
	}

	// TODO(tylersmalley): remove funnel

	return nil
}

func srvTypeAndPortFromFlags(e *serveEnv) (srvType serveType, srvPort uint16, err error) {
	sourceMap := map[serveType]uint{
		serveTypeHTTP:             e.http,
		serveTypeHTTPS:            e.https,
		serveTypeTCP:              e.tcp,
		serveTypeTLSTerminatedTCP: e.tlsTerminatedTCP,
	}

	var srcTypeCount int

	for k, v := range sourceMap {
		if v != 0 {
			if v > math.MaxUint16 {
				return 0, 0, fmt.Errorf("port number %d is too high for %s flag", v, srvType)
			}
			srcTypeCount++
			srvType = k
			srvPort = uint16(v)
		}
	}

	if srcTypeCount > 1 {
		return 0, 0, fmt.Errorf("cannot serve multiple types for a single mount point")
	} else if srcTypeCount == 0 {
		srvType = serveTypeHTTPS
		srvPort = 443
	}

	return srvType, srvPort, nil
}

// isLegacyInvocation helps transition customers who have been using the beta
// CLI to the newer API by returning a translation from the old command to the new command.
// The second result is a boolean that only returns true if the given arguments is a valid
// legacy invocation. If the given args are in the old format but are not valid, it will
// return false and expects the new code path has enough validations to reject the request.
func isLegacyInvocation(subcmd serveMode, args []string) (string, bool) {
	if subcmd == funnel {
		if len(args) != 2 {
			return "", false
		}
		_, err := strconv.ParseUint(args[0], 10, 16)
		return "", err == nil && (args[1] == "on" || args[1] == "off")
	}
	turnOff := len(args) > 1 && args[len(args)-1] == "off"
	if turnOff {
		args = args[:len(args)-1]
	}
	if len(args) == 0 {
		return "", false
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
			return "", false
		}
	}

	var wantLength int
	switch srcType {
	case "https", "http":
		wantLength = 3
	case "tcp", "tls-terminated-tcp":
		wantLength = 2
	default:
		// return non-legacy, and let new code handle validation.
		return "", false
	}
	// The length is either exactlly the same as in "https / <target>"
	// or target is omitted as in "https / off" where omit the off at
	// the top.
	if len(args) != wantLength && !(turnOff && len(args) == wantLength-1) {
		return "", false
	}

	cmd := []string{"tailscale", "serve", "--bg"}
	switch srcType {
	case "https":
		// In the new code, we default to https:443,
		// so we don't need to pass the flag explicitly.
		if srcPortStr != "443" {
			cmd = append(cmd, fmt.Sprintf("--https %s", srcPortStr))
		}
	case "http":
		cmd = append(cmd, fmt.Sprintf("--http %s", srcPortStr))
	case "tcp", "tls-terminated-tcp":
		cmd = append(cmd, fmt.Sprintf("--%s %s", srcType, srcPortStr))
	}

	var mount string
	if srcType == "https" || srcType == "http" {
		mount = args[1]
		if _, err := cleanMountPoint(mount); err != nil {
			return "", false
		}
		if mount != "/" {
			cmd = append(cmd, "--set-path "+mount)
		}
	}

	// If there's no "off" there must always be a target destination.
	// If there is "off", target is optional so check if it exists
	// first before appending it.
	hasTarget := !turnOff || (turnOff && len(args) == wantLength)
	if hasTarget {
		dest := args[len(args)-1]
		if strings.Contains(dest, " ") {
			dest = strconv.Quote(dest)
		}
		cmd = append(cmd, dest)
	}
	if turnOff {
		cmd = append(cmd, "off")
	}

	return strings.Join(cmd, " "), true
}

// removeWebServe removes a web handler from the serve config
// and removes funnel if no remaining mounts exist for the serve port.
// The srvPort argument is the serving port and the mount argument is
// the mount point or registered path to remove.
func (e *serveEnv) removeWebServe(sc *ipn.ServeConfig, dnsName string, srvPort uint16, mount string) error {
	if sc.IsTCPForwardingOnPort(srvPort) {
		return errors.New("cannot remove web handler; currently serving TCP")
	}

	portStr := strconv.Itoa(int(srvPort))
	hp := ipn.HostPort(net.JoinHostPort(dnsName, portStr))

	var targetExists bool
	var mounts []string
	// mount is deduced from e.setPath but it is ambiguous as
	// to whether the user explicitly passed "/" or it was defaulted to.
	if e.setPath == "" {
		targetExists = sc.Web[hp] != nil && len(sc.Web[hp].Handlers) > 0
		if targetExists {
			for mount := range sc.Web[hp].Handlers {
				mounts = append(mounts, mount)
			}
		}
	} else {
		targetExists = sc.WebHandlerExists(hp, mount)
		mounts = []string{mount}
	}

	if !targetExists {
		return errors.New("error: handler does not exist")
	}

	if len(mounts) > 1 {
		msg := fmt.Sprintf("Are you sure you want to delete %d handlers under port %s?", len(mounts), portStr)
		if !e.yes && !promptYesNo(msg) {
			return nil
		}
	}

	sc.RemoveWebHandler(dnsName, srvPort, mounts, true)
	return nil
}

// removeTCPServe removes the TCP forwarding configuration for the
// given srvPort, or serving port.
func (e *serveEnv) removeTCPServe(sc *ipn.ServeConfig, src uint16) error {
	if sc == nil {
		return nil
	}
	if sc.GetTCPPortHandler(src) == nil {
		return errors.New("error: serve config does not exist")
	}
	if sc.IsServingWeb(src) {
		return fmt.Errorf("unable to remove; serving web, not TCP forwarding on serve port %d", src)
	}
	sc.RemoveTCPForwarding(src)
	return nil
}

// cleanURLPath ensures the path is clean and has a leading "/".
func cleanURLPath(urlPath string) (string, error) {
	if urlPath == "" {
		return "/", nil
	}

	// TODO(tylersmalley) verify still needed with path being a flag
	urlPath = cleanMinGWPathConversionIfNeeded(urlPath)
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}

	c := path.Clean(urlPath)
	if urlPath == c || urlPath == c+"/" {
		return urlPath, nil
	}
	return "", fmt.Errorf("invalid mount point %q", urlPath)
}

func (s serveType) String() string {
	switch s {
	case serveTypeHTTP:
		return "http"
	case serveTypeHTTPS:
		return "https"
	case serveTypeTCP:
		return "tcp"
	case serveTypeTLSTerminatedTCP:
		return "tls-terminated-tcp"
	default:
		return "unknownServeType"
	}
}

func (e *serveEnv) stdout() io.Writer {
	if e.testStdout != nil {
		return e.testStdout
	}
	return Stdout
}

func (e *serveEnv) stderr() io.Writer {
	if e.testStderr != nil {
		return e.testStderr
	}
	return Stderr
}
