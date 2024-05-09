// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var renewCmd = &ffcli.Command{
	Name:       "renew",
	ShortUsage: "tailscale renew",
	ShortHelp:  "Reauthenticate and renew the device key",

	LongHelp: strings.TrimSpace(`
HIDDEN: "tailscale renew" triggers reauthentication and renewal of the
device key.)
`),
	FlagSet: upFlagSet,
	Exec: func(ctx context.Context, args []string) error {
		return runRenew(ctx)
	},
}

func runRenew(ctx context.Context) (retErr error) {
	st, err := localClient.Status(ctx)
	if err != nil {
		return fixTailscaledConnectError(err)
	}
	origAuthURL := st.AuthURL

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	watcher, err := localClient.WatchIPNBus(watchCtx, 0)
	if err != nil {
		return err
	}
	defer watcher.Close()

	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-interrupt:
			cancelWatch()
		case <-watchCtx.Done():
		}
	}()

	if err := localClient.StartLoginInteractive(ctx); err != nil {
		return fmt.Errorf("could not call localapi: %w", err)
	}

	for {
		n, err := watcher.Next()
		if err != nil {
			return err
		}
		if n.ErrMessage != nil {
			msg := *n.ErrMessage
			fatalf("backend error: %v\n", msg)
		}
		if url := n.BrowseToURL; url != nil && *url != origAuthURL {
			fmt.Fprintf(Stderr, "\nTo authenticate, visit:\n\n\t%s\n\n", *url)
		}
		if n.LoginFinished != nil {
			fmt.Fprintf(Stderr, "Success.\n")
			return nil
		}
	}
}
