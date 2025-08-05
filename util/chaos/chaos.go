// chaos is a command-line tool and "framework" for generating different
// types of loads based on defined scenarios to a Tailscale control server.
// It can be used to test the control server's performance and resilience.
//
// Scenarios are implemented as subcommands and each can register their own
// flags and options allowing them to be modified at runtime.
package chaos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"tailscale.com/client/tailscale/v2"
	"tailscale.com/safeweb"
	"tailscale.com/tsweb"
	"tailscale.com/util/prompt"

	// Support for prometheus varz in tsweb
	_ "tailscale.com/tsweb/promvarz"
)

var baseArgs struct {
	LoginServer     string `flag:"login-server,Address of the tailcontrol server"`
	Tailnet         string `flag:"tailnet,default=example.com,TailnetSID of the test tailnet"`
	AuthKey         string `flag:"authkey,AuthKey for tailnet in tailcontrol"`
	ApiKey          string `flag:"apikey,API Key for tailcontrol"`
	DebugServer     string `flag:"debug-server,ip:port for a debug webserver"`
	RemoveAll       bool   `flag:"remove-all,Remove all nodes from the tailnet before the scenario starts (if implemented by the scenario), must be passed with --force"`
	Force           bool   `flag:"force,Force the operation without checks"`
	FullTagLabels   bool   `flag:"full-tag-labels,Use full tag values in metric labels, instead of truncating numeric suffixes"`
	NetmapTracker   bool   `flag:"netmap-tracker,default=true,Enable netmap latency tracking"`
	TailcontrolArgs string `flag:"tailcontrol-args,default=,Args and flags passed to tailcontrol"`
}

type NewControlFunc func(loginServer, tailnet, apikey string) (ControlServer, error)

// NewControl is a function that creates a new ControlServer instance.
// It and allow for different implementations of the ControlServer interface
// to be used.
var NewControl NewControlFunc = NewTailControl

// NewChaosCommandEnv creates a new command environment for the chaos tool.
// It is the main entry point for the command-line interface, and where scenarios
// are registered as subcommands.
// It should be called in main, and any alternative implementations of the ControlServer
// should be registered before calling this function by overriding NewControl.
func NewChaosCommandEnv(ctx context.Context) *command.Env {
	root := command.C{
		Name:  filepath.Base(os.Args[0]),
		Usage: "command [flags] ...\nhelp [command]",
		Help:  `A command-line tool for testing load against a tailcontrol server`,

		Commands: []*command.C{
			// Scenarios are registered as additional subcommands
			// and be invoked from the command line with specific flags
			// as the user sees fit.
			joinNNodesCmd,
			ciChurnCmd,

			command.HelpCommand(nil),
			command.VersionCommand(),
			{
				Name: "remove-all-nodes",
				Help: `Removes all nodes currently present in the tailnet, use with caution.`,
				Run: func(env *command.Env) error {
					tc, err := NewControl(baseArgs.LoginServer, baseArgs.Tailnet, baseArgs.ApiKey)
					if err != nil {
						return err
					}

					c := NewChaos(tc)

					return c.RemoveAllNodes(env)
				},
			},
		},
		SetFlags: command.Flags(flax.MustBind, &baseArgs),
		Init: func(env *command.Env) error {
			if baseArgs.DebugServer != "" {
				log.Printf("Starting debug server on %s", baseArgs.DebugServer)
				go func() {
					mux := http.NewServeMux()
					tsweb.Debugger(mux)
					httpServer, err := safeweb.NewServer(safeweb.Config{BrowserMux: mux})
					if err != nil {
						log.Fatalf("safeweb.NewServer: %v", err)
					}
					ln, err := net.Listen("tcp", baseArgs.DebugServer)
					if err != nil {
						log.Fatalf("failed to listen: %v", err)
					}
					defer ln.Close()

					if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
						log.Fatalf("http: %v", err)
					}
				}()
			}

			runLabels := map[string]string{
				"start":            time.Now().Format(time.RFC3339),
				"chaos_args":       strings.Join(os.Args, " "),
				"tailcontrol_args": baseArgs.TailcontrolArgs,
			}
			if build, ok := debug.ReadBuildInfo(); ok {
				for _, setting := range build.Settings {
					runLabels[settingLabel(setting.Key)] = setting.Value
				}
			}
			promauto.NewGauge(prometheus.GaugeOpts{
				Name:        "chaos_run",
				Help:        "details about this chaos run",
				ConstLabels: runLabels,
			}).Set(1)
			return nil
		},
	}

	return root.NewEnv(nil).SetContext(ctx).MergeFlags(true)
}

func settingLabel(key string) string {
	return "build_" + strings.Trim(strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, key), "_")
}

// Chaos is the main structure for the chaos tool.
type Chaos struct {
	Control ControlServer
}

// ControlServer defines the interface for interacting with a Tailscale control server.
type ControlServer interface {
	Tailnet() string
	BaseURL() string
	SetACL(ctx context.Context, pol tailscale.ACL) (*tailscale.ACL, error)
	ListDevices(ctx context.Context) ([]tailscale.Device, error)
	RemoveDevice(ctx context.Context, nodeID string) error
	CreatAuthKey(ctx context.Context, ephemeral bool, tags []string) (string, error)
}

// TailControl is a concrete implementation of the ControlServer interface
// that uses the Tailscale API client to interact with a Tailscale control server.
type TailControl struct {
	c *tailscale.Client
}

// NewTailControl creates a new TailControl instance.
func NewTailControl(loginServer, tailnet, apikey string) (ControlServer, error) {
	c := &tailscale.Client{
		Tailnet: tailnet,
		APIKey:  apikey,
	}
	c.UserAgent = "tailscale-chaos"
	var err error
	c.BaseURL, err = url.Parse(strings.TrimSuffix(loginServer, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	if tailnet == "" {
		return nil, errors.New("tailnet is required for API client")
	}

	if apikey == "" {
		return nil, errors.New("apikey is required for API client")
	}

	return &TailControl{
		c: c,
	}, nil
}

// SetACL sets the ACL for the tailnet.
func (tc *TailControl) SetACL(ctx context.Context, pol tailscale.ACL) (*tailscale.ACL, error) {
	return tc.c.PolicyFile().SetAndGet(ctx, pol, pol.ETag)
}

// Tailnet returns the tailnet domain.
func (tc *TailControl) Tailnet() string {
	return tc.c.Tailnet
}

// BaseURL returns the base URL of the Tailscale control server.
func (tc *TailControl) BaseURL() string {
	return tc.c.BaseURL.String()
}

// ListDevices lists all devices in the tailnet.
func (tc *TailControl) ListDevices(ctx context.Context) ([]tailscale.Device, error) {
	return tc.c.Devices().List(ctx)
}

// RemoveDevice removes a device from the tailnet by its node ID.
func (tc *TailControl) RemoveDevice(ctx context.Context, nodeID string) error {
	return tc.c.Devices().Delete(ctx, nodeID)
}

// CreatAuthKey creates a new Tailscale auth key with the specified options.
func (tc *TailControl) CreatAuthKey(ctx context.Context, eph bool, tags []string) (string, error) {
	var req tailscale.CreateKeyRequest
	req.Capabilities.Devices.Create.Preauthorized = true
	req.Capabilities.Devices.Create.Reusable = true
	req.Capabilities.Devices.Create.Tags = tags
	req.Capabilities.Devices.Create.Ephemeral = eph
	key, err := tc.c.Keys().Create(ctx, req)
	if err != nil {
		return "", err
	}
	return key.Key, err
}

// NewChaos creates a new Chaos instance with the provided ControlServer.
func NewChaos(control ControlServer) *Chaos {
	return &Chaos{
		Control: control,
	}
}

// SetACL sets the ACL for the tailnet.
func (c *Chaos) SetACL(ctx context.Context, pol tailscale.ACL) (*tailscale.ACL, error) {
	return c.Control.SetACL(ctx, pol)
}

const defaultACLs = `
// Example/default ACLs for unrestricted connections.
{
	// Define grants that govern access for users, groups, autogroups, tags,
	// Tailscale IP addresses, and subnet ranges.
	"grants": [
		// Allow all connections.
		// Comment this section out if you want to define specific restrictions.
		{"src": ["*"], "dst": ["*"], "ip": ["*"]},
	],
	// Define users and devices that can use Tailscale SSH.
	"ssh": [
		// Allow all users to SSH into their own devices in check mode.
		// Comment this section out if you want to define specific restrictions.
		{
			"action": "check",
			"src":    ["autogroup:member"],
			"dst":    ["autogroup:self"],
			"users":  ["autogroup:nonroot", "root"],
		},
	],
}
`

// ResetACL resets the ACL for the tailnet to the default policy.
func (c *Chaos) ResetACL(ctx context.Context) error {
	var pol tailscale.ACL
	if err := json.Unmarshal([]byte(defaultACLs), &pol); err != nil {
		return err
	}

	if _, err := c.Control.SetACL(ctx, pol); err != nil {
		return err
	}

	return nil
}

// RemoveAllNodes removes all nodes from the tailnet.
// It prompts the user for confirmation unless the --force flag is set.
func (c *Chaos) RemoveAllNodes(env *command.Env) error {
	if baseArgs.Force {
		log.Printf("Force flag passed, proceeding with removal of all nodes")
	} else if !prompt.YesNo(fmt.Sprintf("Remove all nodes in tailnet %q on tailcontrol %q?", c.Control.Tailnet(), c.Control.BaseURL())) {
		log.Printf("removal of all nodes requested, but not confirmed: aborting removal of all nodes")
		return nil
	}

	if err := c.removeAllNodes(env.Context()); err != nil {
		return err
	}

	return nil
}

func (c *Chaos) removeAllNodes(ctx context.Context) error {
	devs, err := c.Control.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("getting devices: %w", err)
	}

	for _, dev := range devs {
		log.Printf("Deleting device %q (%s)", dev.Name, dev.NodeID)
		if err := c.Control.RemoveDevice(ctx, dev.NodeID); err != nil {
			return fmt.Errorf("deleting device %q (%s): %w", dev.Name, dev.NodeID, err)
		}
	}

	return nil
}
