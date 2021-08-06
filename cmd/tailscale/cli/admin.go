// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/dsnet/golib/jsonfmt"
	"github.com/peterbourgon/ff/v2/ffcli"
)

const tailscaleAPIURL = "https://api.tailscale.com/api"

var adminCmd = &ffcli.Command{
	Name:       "admin",
	ShortUsage: "admin <subcommand> [command flags]",
	ShortHelp:  "Administrate a tailnet",
	LongHelp: strings.TrimSpace(`
The "tailscale admin" command administrates a tailnet through the CLI.
It is a wrapper over the RESTful API served at ` + tailscaleAPIURL + `.
See https://github.com/tailscale/tailscale/blob/main/api.md for more information
about the API itself.

In order for the "admin" command to call the API, it needs an API key,
which is specified by setting the TAILSCALE_API_KEY environment variable.
Also, to easy usage, the tailnet to administrate can be specified through the
TAILSCALE_NET_NAME environment variable, or specified with the -tailnet flag.

Visit https://login.tailscale.com/admin/settings/authkeys in order to obtain
an API key.
`),
	FlagSet: (func() *flag.FlagSet {
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		// TODO(dsnet): Can we determine the default tailnet from what this
		// device is currently part of? Alternatively, when add specific logic
		// to handle auth keys, we can always associate a given key with a
		// specific tailnet.
		fs.StringVar(&adminArgs.tailnet, "tailnet", os.Getenv("TAILSCALE_NET_NAME"), "which tailnet to administrate")
		return fs
	})(),
	// TODO(dsnet): Handle users, groups, dns.
	Subcommands: []*ffcli.Command{{
		Name:       "acl",
		ShortUsage: "acl <subcommand> [command flags]",
		ShortHelp:  "Manage the ACL for a tailnet",
		// TODO(dsnet): Handle preview.
		Subcommands: []*ffcli.Command{{
			Name:       "get",
			ShortUsage: "get",
			ShortHelp:  "Downloads the HuJSON ACL file to stdout",
			Exec:       checkAdminKey(runAdminACLGet),
		}, {
			Name:       "set",
			ShortUsage: "set",
			ShortHelp:  "Uploads the HuJSON ACL file from stdin",
			Exec:       checkAdminKey(runAdminACLSet),
		}},
		Exec: runHelp,
	}, {
		Name:       "devices",
		ShortUsage: "devices <subcommand> [command flags]",
		ShortHelp:  "Manage devices in a tailnet",
		Subcommands: []*ffcli.Command{{
			Name:       "list",
			ShortUsage: "list",
			ShortHelp:  "List all devices in a tailnet",
			Exec:       checkAdminKey(runAdminDevicesList),
		}, {
			Name:       "get",
			ShortUsage: "get <id>",
			ShortHelp:  "Get information about a specific device",
			Exec:       checkAdminKey(runAdminDevicesGet),
		}},
		Exec: runHelp,
	}},
	Exec: runHelp,
}

var adminArgs struct {
	tailnet string // which tailnet to operate upon
}

func checkAdminKey(f func(context.Context, string, []string) error) func(context.Context, []string) error {
	return func(ctx context.Context, args []string) error {
		// TODO(dsnet): We should have a subcommand or flag to manage keys.
		// Use of an environment variable is a temporary hack.
		key := os.Getenv("TAILSCALE_API_KEY")
		if !strings.HasPrefix(key, "tskey-") {
			return errors.New("no API key specified")
		}
		return f(ctx, key, args)
	}
}

func runAdminACLGet(ctx context.Context, key string, args []string) error {
	if len(args) > 0 {
		return flag.ErrHelp
	}
	return adminCallAPI(ctx, key, http.MethodGet, "/v2/tailnet/"+adminArgs.tailnet+"/acl", nil, os.Stdout)
}

func runAdminACLSet(ctx context.Context, key string, args []string) error {
	if len(args) > 0 {
		return flag.ErrHelp
	}
	return adminCallAPI(ctx, key, http.MethodPost, "/v2/tailnet/"+adminArgs.tailnet+"/acl", os.Stdin, os.Stdout)
}

func runAdminDevicesList(ctx context.Context, key string, args []string) error {
	if len(args) > 0 {
		return flag.ErrHelp
	}
	return adminCallAPI(ctx, key, http.MethodGet, "/v2/tailnet/"+adminArgs.tailnet+"/devices", nil, os.Stdout)
}

func runAdminDevicesGet(ctx context.Context, key string, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}
	return adminCallAPI(ctx, key, http.MethodGet, "/v2/device/"+args[0], nil, os.Stdout)
}

func adminCallAPI(ctx context.Context, key, method, path string, in io.Reader, out io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, method, tailscaleAPIURL+path, in)
	req.SetBasicAuth(key, "")
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to receive HTTP response: %w", err)
	}
	b, err = jsonfmt.Format(b)
	if err != nil {
		return fmt.Errorf("failed to format JSON response: %w", err)
	}
	_, err = out.Write(b)
	return err

}
