// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"tailscale.com/internal/client/tailscale"
	"tailscale.com/ipn"
	"tailscale.com/util/clientmetric"
)

// metricBlueprintJoinSuccess counts successful `tailscale join`
// invocations. The matching server-side counter is
// blueprint_join_attempts_total{result="success"}.
var metricBlueprintJoinSuccess = clientmetric.NewCounter("cli_blueprint_join_success")

// metricBlueprintJoinFailure counts unsuccessful `tailscale join`
// invocations regardless of cause. The server-side breakdown lives
// in blueprint_join_attempts_total{result=...}.
var metricBlueprintJoinFailure = clientmetric.NewCounter("cli_blueprint_join_failure")

// metricBlueprintBound is a gauge: 1 when this node was brought up
// via `tailscale join` (i.e. Prefs.BlueprintID is non-empty), 0
// otherwise. Updated on join success and on leave.
var metricBlueprintBound = clientmetric.NewGauge("cli_blueprint_bound")

// joinArgs captures the flags accepted by `tailscale join`. The flag
// set is deliberately small: blueprint, auth-key, and the handful of
// node-local concerns the blueprint has no opinion on (hostname,
// state-dir, operator, ssh).
type joinArgsT struct {
	blueprint string
	authKey   string
	hostname  string
	opUser    string
	runSSH    bool
}

var joinArgs joinArgsT

var joinFlagSet = newJoinFlagSet(&joinArgs)

func newJoinFlagSet(a *joinArgsT) *flag.FlagSet {
	fs := newFlagSet("join")
	fs.StringVar(&a.blueprint, "blueprint", "", `Blueprint to bind this node to, e.g. "bp:github-connector"`)
	fs.StringVar(&a.authKey, "auth-key", "", "OAuth client secret paired with the blueprint")
	fs.StringVar(&a.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
	fs.StringVar(&a.opUser, "operator", "", "Unix username to allow to operate on tailscaled without sudo")
	fs.BoolVar(&a.runSSH, "ssh", false, "run a Tailscale SSH server, permitting access per tailnet admin's declared policy")
	return fs
}

var joinCmd = &ffcli.Command{
	Name:       "join",
	ShortUsage: "tailscale join --blueprint=<bp:id> --auth-key=<oauth-secret>",
	ShortHelp:  "Bind this node to a Blueprint and bring it up",
	LongHelp: strings.TrimSpace(`
"tailscale join" connects this machine to a Tailscale tailnet
using a Blueprint definition stored in the tailnet's ACL.

Unlike "tailscale up", a blueprint-bound node delegates its
configuration to the control plane: tags, advertised routes, app
connector advertisement, services served, hostname, operator, SSH,
and DNS acceptance are owned by the blueprint and are reconciled
on every map update. Subsequent attempts to edit those fields via
"tailscale set" will be rejected.

To detach this node, run "tailscale leave".
`),
	FlagSet: joinFlagSet,
	Exec: func(ctx context.Context, args []string) error {
		return runJoin(ctx, args, &joinArgs)
	},
}

// blueprintIDFromFlag extracts the bare <id> portion from the user's
// --blueprint flag value. The spec accepts the prefixed form
// "bp:<id>"; this helper also accepts the bare "<id>" for shell
// ergonomics and validates that <id> looks like a Blueprint ID
// (letter-start, alphanumerics and dashes only).
func blueprintIDFromFlag(s string) (string, error) {
	if s == "" {
		return "", errors.New("--blueprint is required (e.g. --blueprint=bp:github-connector)")
	}
	id := strings.TrimPrefix(s, "bp:")
	if id == "" {
		return "", fmt.Errorf("--blueprint value %q is empty after stripping the \"bp:\" prefix", s)
	}
	if !isASCIILetter(id[0]) {
		return "", fmt.Errorf("--blueprint id %q must start with a letter", id)
	}
	for _, b := range []byte(id) {
		if !isASCIILetter(b) && !isASCIIDigit(b) && b != '-' {
			return "", fmt.Errorf("--blueprint id %q must contain only letters, digits, and dashes", id)
		}
	}
	return id, nil
}

func isASCIILetter(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }
func isASCIIDigit(b byte) bool  { return b >= '0' && b <= '9' }

// runJoin implements the `tailscale join` subcommand. It validates
// the blueprint ID, resolves the OAuth client secret into an auth
// key via the existing HookResolveAuthKey hook, and calls Start with
// a Prefs that carries Prefs.BlueprintID so the daemon (and
// subsequent `tailscale set` calls) know this node is bound.
func runJoin(ctx context.Context, args []string, ja *joinArgsT) (retErr error) {
	defer func() {
		if retErr != nil {
			metricBlueprintJoinFailure.Add(1)
		}
	}()
	if len(args) > 0 {
		return fmt.Errorf("unexpected positional arguments: %q", args)
	}
	id, err := blueprintIDFromFlag(ja.blueprint)
	if err != nil {
		return err
	}
	if ja.authKey == "" {
		return errors.New("--auth-key is required (the OAuth client secret paired with the blueprint)")
	}

	st, err := localClient.Status(ctx)
	if err != nil {
		return fmt.Errorf("reading status: %w", err)
	}
	if st.BackendState == ipn.Running.String() && st.Self != nil && st.CurrentTailnet != nil {
		// We could allow a re-join, but the spec defines a join as a
		// fresh registration. Refuse and tell the user to leave first.
		return errors.New("this node is already up; run 'tailscale leave' or 'tailscale logout' first")
	}

	prefs := ipn.NewPrefs()
	prefs.BlueprintID = id
	if ja.hostname != "" {
		prefs.Hostname = ja.hostname
	}
	if ja.opUser != "" {
		prefs.OperatorUser = ja.opUser
	}
	if ja.runSSH {
		prefs.RunSSH = true
	}
	prefs.WantRunning = true

	if err := localClient.CheckPrefs(ctx, prefs); err != nil {
		return fmt.Errorf("validating prefs: %w", err)
	}

	authKey := ja.authKey
	if f, ok := tailscale.HookResolveAuthKey.GetOk(); ok {
		// The OAuth-client-secret -> auth-key exchange. The exchange
		// itself validates the secret against the blueprint's paired
		// client server-side.
		authKey, err = f(ctx, ja.authKey, prefs.AdvertiseTags)
		if err != nil {
			return fmt.Errorf("exchanging OAuth client secret for auth key: %w", err)
		}
	}

	if err := localClient.Start(ctx, ipn.Options{
		AuthKey:     authKey,
		UpdatePrefs: prefs,
	}); err != nil {
		return fmt.Errorf("starting tailscale: %w", err)
	}

	metricBlueprintJoinSuccess.Add(1)
	metricBlueprintBound.Set(1)
	fmt.Printf("Bound to blueprint bp:%s\n", id)
	return nil
}
