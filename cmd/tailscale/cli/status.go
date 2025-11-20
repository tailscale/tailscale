// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/toqueteos/webbrowser"
	"golang.org/x/net/idna"
	"tailscale.com/feature"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/util/dnsname"
)

var statusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "tailscale status [--active] [--web] [--json]",
	ShortHelp:  "Show state of tailscaled and its connections",
	LongHelp: strings.TrimSpace(`

JSON FORMAT

Warning: this format has changed between releases and might change more
in the future.

For a description of the fields, see the "type Status" declaration at:

https://github.com/tailscale/tailscale/blob/main/ipn/ipnstate/ipnstate.go

(and be sure to select branch/tag that corresponds to the version
 of Tailscale you're running)

`),
	Exec: runStatus,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("status")
		fs.BoolVar(&statusArgs.json, "json", false, "output in JSON format (WARNING: format subject to change)")
		fs.BoolVar(&statusArgs.web, "web", false, "run webserver with HTML showing status")
		fs.BoolVar(&statusArgs.active, "active", false, "filter output to only peers with active sessions (not applicable to web mode)")
		fs.BoolVar(&statusArgs.self, "self", true, "show status of local machine")
		fs.BoolVar(&statusArgs.peers, "peers", true, "show status of peers")
		fs.StringVar(&statusArgs.listen, "listen", "127.0.0.1:8384", "listen address for web mode; use port 0 for automatic")
		fs.BoolVar(&statusArgs.browser, "browser", true, "Open a browser in web mode")
		fs.BoolVar(&statusArgs.header, "header", false, "show column headers in table format")
		return fs
	})(),
}

var statusArgs struct {
	json    bool   // JSON output mode
	web     bool   // run webserver
	listen  string // in web mode, webserver address to listen on, empty means auto
	browser bool   // in web mode, whether to open browser
	active  bool   // in CLI mode, filter output to only peers with active sessions
	self    bool   // in CLI mode, show status of local machine
	peers   bool   // in CLI mode, show status of peer machines
	header  bool   // in CLI mode, show column headers in table format
}

const mullvadTCD = "mullvad.ts.net."

func runStatus(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected non-flag arguments to 'tailscale status'")
	}
	getStatus := localClient.Status
	if !statusArgs.peers {
		getStatus = localClient.StatusWithoutPeers
	}
	st, err := getStatus(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	if statusArgs.json {
		if statusArgs.active {
			for peer, ps := range st.Peer {
				if !ps.Active {
					delete(st.Peer, peer)
				}
			}
		}
		j, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			return err
		}
		printf("%s", j)
		return nil
	}
	if statusArgs.web {
		ln, err := net.Listen("tcp", statusArgs.listen)
		if err != nil {
			return err
		}
		statusURL := netmon.HTTPOfListener(ln)
		printf("Serving Tailscale status at %v ...\n", statusURL)
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		if statusArgs.browser {
			go webbrowser.Open(statusURL)
		}
		err = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.RequestURI != "/" {
				http.NotFound(w, r)
				return
			}
			st, err := localClient.Status(ctx)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			st.WriteHTML(w)
		}))
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	printHealth := func() {
		printf("# Health check:\n")
		for _, m := range st.Health {
			printf("#     - %s\n", m)
		}
	}

	description, ok := isRunningOrStarting(st)
	if !ok {
		// print health check information if we're in a weird state, as it might
		// provide context about why we're in that weird state.
		if len(st.Health) > 0 && (st.BackendState == ipn.Starting.String() || st.BackendState == ipn.NoState.String()) {
			printHealth()
			outln()
		}
		outln(description)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(Stdout, 0, 0, 2, ' ', 0)
	f := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	if statusArgs.header {
		fmt.Fprintln(w, "IP\tHostname\tOwner\tOS\tStatus\t")
		fmt.Fprintln(w, "--\t--------\t-----\t--\t------\t")
	}

	printPS := func(ps *ipnstate.PeerStatus) {
		f("%s\t%s\t%s\t%s\t",
			firstIPString(ps.TailscaleIPs),
			dnsOrQuoteHostname(st, ps),
			ownerLogin(st, ps),
			ps.OS,
		)
		relay := ps.Relay
		anyTraffic := ps.TxBytes != 0 || ps.RxBytes != 0
		var offline string
		if !ps.Online {
			offline = "; offline" + lastSeenFmt(ps.LastSeen)
		}
		if !ps.Active {
			if ps.ExitNode {
				f("idle; exit node" + offline)
			} else if ps.ExitNodeOption {
				f("idle; offers exit node" + offline)
			} else if anyTraffic {
				f("idle" + offline)
			} else if !ps.Online {
				f("offline" + lastSeenFmt(ps.LastSeen))
			} else {
				f("-")
			}
		} else {
			f("active; ")
			if ps.ExitNode {
				f("exit node; ")
			} else if ps.ExitNodeOption {
				f("offers exit node; ")
			}
			if relay != "" && ps.CurAddr == "" && ps.PeerRelay == "" {
				f("relay %q", relay)
			} else if ps.CurAddr != "" {
				f("direct %s", ps.CurAddr)
			} else if ps.PeerRelay != "" {
				f("peer-relay %s", ps.PeerRelay)
			}
			if !ps.Online {
				f(offline)
			}
		}
		if anyTraffic {
			f(", tx %d rx %d", ps.TxBytes, ps.RxBytes)
		}
		f("\t\n")
	}

	if statusArgs.self && st.Self != nil {
		printPS(st.Self)
	}

	locBasedExitNode := false
	if statusArgs.peers {
		var peers []*ipnstate.PeerStatus
		for _, peer := range st.Peers() {
			ps := st.Peer[peer]
			if ps.ShareeNode {
				continue
			}
			if ps.ExitNodeOption && !ps.ExitNode && strings.HasSuffix(ps.DNSName, mullvadTCD) {
				// Mullvad exit nodes are only shown with the `exit-node list` command.
				locBasedExitNode = true
				continue
			}
			peers = append(peers, ps)
		}
		ipnstate.SortPeers(peers)
		for _, ps := range peers {
			if statusArgs.active && !ps.Active {
				continue
			}
			printPS(ps)
		}
	}
	w.Flush()

	if locBasedExitNode {
		outln()
		printf("# To see the full list of exit nodes, including location-based exit nodes, run `tailscale exit-node list`  \n")
	}
	if len(st.Health) > 0 {
		outln()
		printHealth()
	}
	if f, ok := hookPrintFunnelStatus.GetOk(); ok {
		f(ctx)
	}
	return nil
}

var hookPrintFunnelStatus feature.Hook[func(context.Context)]

// isRunningOrStarting reports whether st is in state Running or Starting.
// It also returns a description of the status suitable to display to a user.
func isRunningOrStarting(st *ipnstate.Status) (description string, ok bool) {
	switch st.BackendState {
	default:
		return fmt.Sprintf("unexpected state: %s", st.BackendState), false
	case ipn.Stopped.String():
		return "Tailscale is stopped.", false
	case ipn.NeedsLogin.String():
		s := "Logged out."
		if st.AuthURL != "" {
			s += fmt.Sprintf("\nLog in at: %s", st.AuthURL)
		}
		return s, false
	case ipn.NeedsMachineAuth.String():
		return "Machine is not yet approved by tailnet admin.", false
	case ipn.Running.String(), ipn.Starting.String():
		return st.BackendState, true
	}
}

func dnsOrQuoteHostname(st *ipnstate.Status, ps *ipnstate.PeerStatus) string {
	baseName := dnsname.TrimSuffix(ps.DNSName, st.MagicDNSSuffix)
	if baseName != "" {
		if strings.HasPrefix(baseName, "xn-") {
			if u, err := idna.ToUnicode(baseName); err == nil {
				return fmt.Sprintf("%s (%s)", baseName, u)
			}
		}
		return baseName
	}
	return fmt.Sprintf("(%q)", dnsname.SanitizeHostname(ps.HostName))
}

func ownerLogin(st *ipnstate.Status, ps *ipnstate.PeerStatus) string {
	// We prioritize showing the name of the sharer as the owner of a node if
	// it's different from the node's user. This is less surprising: if user B
	// from a company shares user's C node from the same company with user A who
	// don't know user C, user A might be surprised to see user C listed in
	// their netmap. We've historically (2021-01..2023-08) always shown the
	// sharer's name in the UI. Perhaps we want to show both here? But the CLI's
	// a bit space constrained.
	uid := cmp.Or(ps.AltSharerUserID, ps.UserID)
	if uid.IsZero() {
		return "-"
	}
	u, ok := st.User[uid]
	if !ok {
		return fmt.Sprint(uid)
	}
	if i := strings.Index(u.LoginName, "@"); i != -1 {
		return u.LoginName[:i+1]
	}
	return u.LoginName
}

func firstIPString(v []netip.Addr) string {
	if len(v) == 0 {
		return ""
	}
	return v[0].String()
}
