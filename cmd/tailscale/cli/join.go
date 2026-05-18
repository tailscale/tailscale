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
	"tailscale.com/tailcfg"
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
	blueprint   string
	authKey     string
	loginServer string
	hostname    string
	opUser      string
	runSSH      bool
}

var joinArgs joinArgsT

var joinFlagSet = newJoinFlagSet(&joinArgs)

func newJoinFlagSet(a *joinArgsT) *flag.FlagSet {
	fs := newFlagSet("join")
	fs.StringVar(&a.blueprint, "blueprint", "", `Blueprint to bind this node to, e.g. "bp:github-connector"`)
	fs.StringVar(&a.authKey, "auth-key", "", "OAuth client secret paired with the blueprint")
	fs.StringVar(&a.loginServer, "login-server", "", "base URL of the control server, e.g. http://localhost:31544 for a local devcontrol; defaults to the daemon's currently-configured URL (or controlplane.tailscale.com)")
	fs.StringVar(&a.hostname, "hostname", "", "hostname to use instead of the one provided by the OS")
	fs.StringVar(&a.opUser, "operator", "", "Unix username to allow to operate on tailscaled without sudo")
	fs.BoolVar(&a.runSSH, "ssh", false, "run a Tailscale SSH server, permitting access per tailnet admin's declared policy")
	return fs
}

var joinCmd = &ffcli.Command{
	Name:       "join",
	ShortUsage: "tailscale join [<bp:id>] [--blueprint=<bp:id>] --auth-key=<oauth-secret>",
	ShortHelp:  "Bind this node to a Blueprint and bring it up",
	LongHelp: strings.TrimSpace(`
"tailscale join" connects this machine to a Tailscale tailnet
using a Blueprint definition stored in the tailnet's ACL.

The blueprint to bind to may be given either as the first
positional argument or via --blueprint, and may be written either
as "bp:<id>" or as the bare "<id>". The four forms below are
equivalent:
  tailscale join --blueprint=bp:foo --auth-key=...
  tailscale join --blueprint=foo    --auth-key=...
  tailscale join bp:foo             --auth-key=...
  tailscale join foo                --auth-key=...

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

// normalizeBlueprintArg returns the "bp:<id>" form of s, prepending
// "bp:" if missing. It does not validate the body; callers should
// pass the result (or the bare id) to blueprintIDFromFlag.
func normalizeBlueprintArg(s string) string {
	if s == "" || strings.HasPrefix(s, "bp:") {
		return s
	}
	return "bp:" + s
}

// resolveBlueprintArg picks the blueprint id from either the first
// positional argument or the --blueprint flag value. Both forms
// accept either "bp:<id>" or the bare "<id>"; the two are normalized
// (by prepending "bp:" if missing) before comparison, so passing the
// same id in both forms is accepted silently. Mismatched values are
// reported with the user's original strings so the error makes clear
// which form came from where.
func resolveBlueprintArg(positional, flagVal string) (string, error) {
	if positional == "" && flagVal == "" {
		return "", errors.New("tailscale join requires a blueprint. Pass it as --blueprint=<id> or as the first positional argument")
	}
	if positional != "" && flagVal != "" {
		if normalizeBlueprintArg(positional) != normalizeBlueprintArg(flagVal) {
			return "", fmt.Errorf("blueprint specified twice: '%s' (positional) and '%s' (--blueprint). Pass one or the other",
				normalizeBlueprintArg(positional), normalizeBlueprintArg(flagVal))
		}
		return blueprintIDFromFlag(flagVal)
	}
	if positional != "" {
		return blueprintIDFromFlag(positional)
	}
	return blueprintIDFromFlag(flagVal)
}

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
	if len(args) > 1 {
		return fmt.Errorf("too many positional arguments: %q (tailscale join accepts at most one blueprint id)", args)
	}
	var positional string
	if len(args) == 1 {
		positional = args[0]
	}
	id, err := resolveBlueprintArg(positional, ja.blueprint)
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
	if ja.loginServer != "" {
		prefs.ControlURL = ja.loginServer
	}
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
		// validates the secret against the blueprint's paired client
		// server-side, which is itself scoped to "tag:bp//<id>"; we
		// synthesize that tag from the blueprint id here so the hook,
		// which requires a non-empty tag set, accepts the request
		// without --advertise-tags (a flag join intentionally does
		// not expose, because the blueprint owns the node's tags).
		bpTag := "tag:" + tailcfg.BlueprintTagNamespacePrefix + id
		authKey, err = f(ctx, ja.authKey, []string{bpTag})
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
	// Start alone applies prefs and stores the auth key; the daemon
	// then waits in NeedsLogin until something asks it to log in.
	// tailscale up handles this by calling StartLoginInteractive when
	// the daemon has no node key (see cmd/tailscale/cli/up.go). join
	// is by definition a fresh registration -- the earlier status
	// check refuses to run if BackendState is already Running -- so
	// we always trigger the login here.
	if err := localClient.StartLoginInteractive(ctx); err != nil {
		return fmt.Errorf("kicking off blueprint join login: %w", err)
	}

	metricBlueprintJoinSuccess.Add(1)
	metricBlueprintBound.Set(1)
	fmt.Printf("Bound to blueprint bp:%s\n", id)
	return nil
}
