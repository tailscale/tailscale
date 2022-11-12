// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/ipn"
	"tailscale.com/util/mak"
)

var serveCmd = newServeCommand(&serveEnv{})

// newServeCommand returns a new "serve" subcommand using e as its environmment.
func newServeCommand(e *serveEnv) *ffcli.Command {
	return &ffcli.Command{
		Name:       "serve",
		ShortHelp:  "TODO",
		ShortUsage: "serve {show-config|https|tcp|ingress} <args>",
		LongHelp:   "", // TODO
		Exec:       e.runServe,
		FlagSet:    e.newFlags("serve", func(fs *flag.FlagSet) {}),
		Subcommands: []*ffcli.Command{
			{
				Name:      "show-config",
				Exec:      e.runServeShowConfig,
				ShortHelp: "show current serve config",
			},
			{
				Name:      "tcp",
				Exec:      e.runServeTCP,
				ShortHelp: "add or remove a TCP port forward",
				FlagSet: e.newFlags("serve-tcp", func(fs *flag.FlagSet) {
					fs.BoolVar(&e.terminateTLS, "terminate-tls", false, "terminate TLS before forwarding TCP connection")
				}),
			},
			{
				Name:      "ingress",
				Exec:      e.runServeIngress,
				ShortHelp: "enable or disable ingress",
				FlagSet:   e.newFlags("serve-ingress", func(fs *flag.FlagSet) {}),
			},
		},
	}
}

// serveEnv is the environment the serve command runs within. All I/O should be
// done via serveEnv methods so that it can be faked out for tests.
//
// It also contains the flags, as registered with newServeCommand.
type serveEnv struct {
	// flags
	terminateTLS bool

	// optional stuff for tests:
	testFlagOut        io.Writer
	testGetServeConfig func(context.Context) (*ipn.ServeConfig, error)
	testSetServeConfig func(context.Context, *ipn.ServeConfig) error
	testStdout         io.Writer
}

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

func (e *serveEnv) getServeConfig(ctx context.Context) (*ipn.ServeConfig, error) {
	if e.testGetServeConfig != nil {
		return e.testGetServeConfig(ctx)
	}
	return localClient.GetServeConfig(ctx)
}

func (e *serveEnv) setServeConfig(ctx context.Context, c *ipn.ServeConfig) error {
	if e.testSetServeConfig != nil {
		return e.testSetServeConfig(ctx, c)
	}
	return localClient.SetServeConfig(ctx, c)
}

func (e *serveEnv) stdout() io.Writer {
	if e.testStdout != nil {
		return e.testStdout
	}
	return os.Stdout
}

func (e *serveEnv) runServe(ctx context.Context, args []string) error {
	panic("TODO")
}

func (e *serveEnv) runServeShowConfig(ctx context.Context, args []string) error {
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	j, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	j = append(j, '\n')
	e.stdout().Write(j)
	return nil
}

func (e *serveEnv) runServeTCP(ctx context.Context, args []string) error {
	panic("TODO")
}

func (e *serveEnv) runServeIngress(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return flag.ErrHelp
	}
	var on bool
	switch args[0] {
	case "on", "off":
		on = args[0] == "on"
	default:
		return flag.ErrHelp
	}
	sc, err := e.getServeConfig(ctx)
	if err != nil {
		return err
	}
	var key ipn.HostPort = "foo:123" // TODO(bradfitz,shayne): fix
	if on && sc != nil && sc.AllowIngress[key] ||
		!on && (sc == nil || !sc.AllowIngress[key]) {
		// Nothing to do.
		return nil
	}
	if sc == nil {
		sc = &ipn.ServeConfig{}
	}
	if on {
		mak.Set(&sc.AllowIngress, "foo:123", true)
	} else {
		delete(sc.AllowIngress, "foo:123")
	}
	return e.setServeConfig(ctx, sc)
}
