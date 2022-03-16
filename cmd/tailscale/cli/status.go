// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"github.com/toqueteos/webbrowser"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/interfaces"
	"tailscale.com/util/dnsname"
)

var statusCmd = &ffcli.Command{
	Name:       "status",
	ShortUsage: "status [--active] [--web] [--json]",
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
}

func runStatus(ctx context.Context, args []string) error {
	st, err := tailscale.Status(ctx)
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
		statusURL := interfaces.HTTPOfListener(ln)
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
			st, err := tailscale.Status(ctx)
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

	description, ok := isRunningOrStarting(st)
	if !ok {
		outln(description)
		os.Exit(1)
	}

	if len(st.Health) > 0 {
		printf("# Health check:\n")
		for _, m := range st.Health {
			printf("#     - %s\n", m)
		}
		outln()
	}

	var buf bytes.Buffer
	f := func(format string, a ...any) { fmt.Fprintf(&buf, format, a...) }
	printPS := func(ps *ipnstate.PeerStatus) {
		f("%-15s %-20s %-12s %-7s ",
			firstIPString(ps.TailscaleIPs),
			dnsOrQuoteHostname(st, ps),
			ownerLogin(st, ps),
			ps.OS,
		)
		relay := ps.Relay
		anyTraffic := ps.TxBytes != 0 || ps.RxBytes != 0
		var offline string
		if !ps.Online {
			offline = "; offline"
		}
		if !ps.Active {
			if ps.ExitNode {
				f("idle; exit node" + offline)
			} else if ps.ExitNodeOption {
				f("idle; offers exit node" + offline)
			} else if anyTraffic {
				f("idle" + offline)
			} else if !ps.Online {
				f("offline")
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
			if relay != "" && ps.CurAddr == "" {
				f("relay %q", relay)
			} else if ps.CurAddr != "" {
				f("direct %s", ps.CurAddr)
			}
			if !ps.Online {
				f("; offline")
			}
		}
		if anyTraffic {
			f(", tx %d rx %d", ps.TxBytes, ps.RxBytes)
		}
		f("\n")
	}

	if statusArgs.self && st.Self != nil {
		printPS(st.Self)
	}
	if statusArgs.peers {
		var peers []*ipnstate.PeerStatus
		for _, peer := range st.Peers() {
			ps := st.Peer[peer]
			if ps.ShareeNode {
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
	Stdout.Write(buf.Bytes())
	return nil
}

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
		return "Machine is not yet authorized by tailnet admin.", false
	case ipn.Running.String(), ipn.Starting.String():
		return st.BackendState, true
	}
}

func dnsOrQuoteHostname(st *ipnstate.Status, ps *ipnstate.PeerStatus) string {
	baseName := dnsname.TrimSuffix(ps.DNSName, st.MagicDNSSuffix)
	if baseName != "" {
		return baseName
	}
	return fmt.Sprintf("(%q)", dnsname.SanitizeHostname(ps.HostName))
}

func ownerLogin(st *ipnstate.Status, ps *ipnstate.PeerStatus) string {
	if ps.UserID.IsZero() {
		return "-"
	}
	u, ok := st.User[ps.UserID]
	if !ok {
		return fmt.Sprint(ps.UserID)
	}
	if i := strings.Index(u.LoginName, "@"); i != -1 {
		return u.LoginName[:i+1]
	}
	return u.LoginName
}

func firstIPString(v []netaddr.IP) string {
	if len(v) == 0 {
		return ""
	}
	return v[0].String()
}
