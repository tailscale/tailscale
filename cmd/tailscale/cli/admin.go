// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Admin commands.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/client/tailscale"
)

var adminCmd = &ffcli.Command{
	Name:     "admin",
	Exec:     runAdmin,
	LongHelp: `"tailscale admin" contains admin commands to manage a Tailscale network.`,
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("admin")
		fs.StringVar(&adminArgs.apiBase, "api-server", "https://api.tailscale.com", "which Tailscale server instance to use. Ignored when --token-file is empty.")
		fs.StringVar(&adminArgs.tokenFile, "token-file", "", "if non-empty, filename containing API token to use. If empty, authentication is done via the active Tailscale control plane connection.")
		fs.StringVar(&adminArgs.tailnet, "tailnet", "", "Tailnet to query or edit. Required if token-file is used. Must be blank if token-file is blank, in which case the tailnet used is the same as the active tailnet.")
		return fs
	})(),
	Subcommands: []*ffcli.Command{
		newTailnetACLGetCmd(),
		newTailnetDeviceListCmd(),
		newTailnetKeyListCmd(),
	},
}

var adminArgs struct {
	tokenFile string
	tailnet   string
	apiBase   string
}

func runAdmin(ctx context.Context, args []string) error {
	if len(args) > 0 {
		return errors.New("unknown command; see 'tailscale admin --help'")
	}
	return errors.New("see 'tailscale admin --help'")
}

type adminClient struct {
	apiBase string // e.g. "https://api.tailscale.com"
	token   string // non-empty if using token-based auth
	hc      *http.Client
	tailnet string // always non-empty
}

func getAdminHTTPClient() (*adminClient, error) {
	tokenFile := adminArgs.tokenFile
	tailnet := adminArgs.tailnet
	apiBase := adminArgs.apiBase
	if (tokenFile != "") != (tailnet != "") {
		return nil, errors.New("--token-file and --tailnet must both be blank or both be specified")
	}
	if tailnet == "" {
		st, err := tailscale.StatusWithoutPeers(context.Background())
		if err != nil {
			return nil, err
		}
		if st.BackendState != "Running" {
			return nil, fmt.Errorf("Tailscale must be running; currently in state %q", st.BackendState)
		}
		if st.CurrentTailnet == nil {
			return nil, fmt.Errorf("no CurrentTailnet in status")
		}
		tailnet = st.CurrentTailnet.Name
		// TODO(bradfitz): put apiBase in *ipnstate.TailnetStatus? update apiBase here?
	}
	ac := &adminClient{
		tailnet: tailnet,
		apiBase: apiBase,
	}

	if tokenFile != "" {
		v, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, err
		}
		token := strings.TrimSpace(string(v))
		if token == "" || strings.Contains(token, "\n") {
			return nil, fmt.Errorf("expect exactly 1 line in API token file %v", tokenFile)
		}
		ac.token = token
		ac.hc = http.DefaultClient
	} else {
		// Otherwise, proxy via the local tailscaled and use its identity.
		ac.hc = &http.Client{Transport: apiViaTailscaledTransport{}}
		ac.apiBase = "http://local-tailscaled.sock"
	}
	return ac, nil
}

func newTailnetDeviceListCmd() *ffcli.Command {
	var fields string
	const sub = "tailnet-device-list"
	fs := newFlagSet(sub)
	fs.StringVar(&fields, "fields", "default", "comma-separated fields to include in response or 'default', 'all'")
	return &ffcli.Command{
		Name:      sub,
		ShortHelp: "list devices",
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			ac, err := getAdminHTTPClient()
			if err != nil {
				return err
			}
			q := url.Values{"fields": []string{fields}}
			return writeResJSON(ac.hc.Get(ac.apiBase + "/api/v2/tailnet/" + ac.tailnet + "/devices?" + q.Encode()))
		},
	}
}

func newTailnetKeyListCmd() *ffcli.Command {
	const sub = "tailnet-key-list"
	return &ffcli.Command{
		Name:      sub,
		ShortHelp: "list keys or specific key (with keyID as argument)",
		Exec: func(ctx context.Context, args []string) error {
			var suf string
			if len(args) == 1 {
				suf = "/" + args[0]
			} else if len(args) > 1 {
				return errors.New("too many arguments")
			}
			ac, err := getAdminHTTPClient()
			if err != nil {
				return err
			}
			return writeResJSON(ac.hc.Get(ac.apiBase + "/api/v2/tailnet/" + ac.tailnet + "/keys" + suf))
		},
	}
}

func newTailnetACLGetCmd() *ffcli.Command {
	var asJSON bool // true is JSON, false is HuJSON
	const sub = "tailnet-acl-get"
	fs := newFlagSet(sub)
	fs.BoolVar(&asJSON, "json", false, "if true, return ACL is JSON format. The default of false means to use the original HuJSON JSON superset form that allows comments and trailing commas.")
	return &ffcli.Command{
		Name:      sub,
		ShortHelp: "list Tailnet ACL/config policy",
		FlagSet:   fs,
		Exec: func(ctx context.Context, args []string) error {
			ac, err := getAdminHTTPClient()
			if err != nil {
				return err
			}
			req, err := http.NewRequest("GET", ac.apiBase+"/api/v2/tailnet/"+ac.tailnet+"/acl", nil)
			if err != nil {
				return err
			}
			if asJSON {
				req.Header.Set("Accept", "application/json")
			}
			res, err := ac.hc.Do(req)
			if err != nil {
				return err
			}
			if asJSON {
				return writeResJSON(res, err)
			}
			defer res.Body.Close()
			if res.StatusCode != 200 {
				body, _ := io.ReadAll(res.Body)
				return fmt.Errorf("%v: %s", res.Status, body)
			}
			all, err := io.ReadAll(res.Body)
			if err != nil {
				return err
			}
			var buf bytes.Buffer
			buf.Write(all)
			ensureTrailingNewline(&buf)
			os.Stdout.Write(buf.Bytes())
			return nil
		},
	}
}

// apiViaTailscaledTransport is an http.RoundTripper that makes
// Tailscale API HTTP requests via the localapi to tailscaled,
// which then forwards them on over Noise.
type apiViaTailscaledTransport struct{}

func (apiViaTailscaledTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return tailscale.DoLocalRequest(r)
}

func ensureTrailingNewline(buf *bytes.Buffer) {
	if buf.Len() > 0 && buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
}

func writeResJSON(res *http.Response, err error) error {
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%v: %s", res.Status, body)
	}
	all, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, all, "", "\t"); err != nil {
		return err
	}
	ensureTrailingNewline(&buf)
	os.Stdout.Write(buf.Bytes())
	return nil
}
