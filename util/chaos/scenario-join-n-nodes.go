package chaos

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"runtime/pprof"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

var joinNNodesArgs struct {
	Count                 int           `flag:"node-count,default=1,Number of nodes to join to the network"`
	Verbose               int           `flag:"verbose,default=0,Print verbose output, 0: no, 1: yes, 2: very verbose"`
	JoinTimeout           time.Duration `flag:"join-timeout,default=30s,Timeout for a node joining the tailnet"`
	JoinParallelism       int           `flag:"join-parallelism,default=50,Number of nodes to join in parallel"`
	MemoryHeapProfilePath string        `flag:"heap-pprof-path,Save a memory profile after the main step to this path"`
	NodeType              string        `flag:"node-type,default=direct,Type of node to create, one of: direct (lightweight) or tsnet (full)"`
	OutputDir             string        `flag:"output-dir,Directory to save output files"`
}

var joinNNodesCmd = &command.C{
	Name: "join-n-nodes",
	Help: `Join N nodes to a tailscale network.`,

	Run:      command.Adapt(runJoinNNNodes),
	SetFlags: command.Flags(flax.MustBind, &joinNNodesArgs),
}

func runJoinNNNodes(env *command.Env) error {
	tc, err := NewControl(baseArgs.LoginServer, baseArgs.Tailnet, baseArgs.ApiKey)
	if err != nil {
		return err
	}

	chaos := NewChaos(tc)

	authKey := baseArgs.AuthKey
	if authKey == "" {
		if baseArgs.ApiKey == "" {
			return fmt.Errorf("either --authkey or --apikey is required")
		}
		log.Printf("Auth key not provided; creating one...")
		key, err := chaos.Control.CreatAuthKey(env.Context(), false, nil)
		if err != nil {
			return err
		}

		authKey = key
	}
	opts := NodeOpts{
		loginServer: baseArgs.LoginServer,
		authKey:     authKey,
		ephemeral:   true,
	}

	setVerboseOptionsFromFlag(&opts, joinNNodesArgs.Verbose)

	var nm *NodeMap

	s := Scenario{
		BeforeSteps: func() error {
			if baseArgs.RemoveAll {
				if err := chaos.RemoveAllNodes(env); err != nil {
					return fmt.Errorf("removing all nodes: %w", err)
				}
			}
			return nil
		},
		Steps: []Step{
			{
				Run: func() error {
					var err error
					log.Printf("Login server: %s, authkey: %s", opts.loginServer, opts.authKey)
					log.Printf("Creating %d nodes", joinNNodesArgs.Count)
					nm, err = NewNodeMapWithNodes(env.Context(), nodeFuncFromFlag(joinNNodesArgs.NodeType), joinNNodesArgs.Count, opts)
					if err != nil {
						return fmt.Errorf("creating nodes: %w", err)
					}

					log.Printf("Joining %d nodes to the network", joinNNodesArgs.Count)

					if err := nm.StartAll(env.Context(), joinNNodesArgs.JoinParallelism); err != nil {
						return fmt.Errorf("starting nodes: %w", err)
					}

					ctx, cancel := context.WithTimeout(env.Context(), joinNNodesArgs.JoinTimeout)
					defer cancel()

					ready := time.Now()
					if err := nm.WaitForReady(ctx); err != nil {
						return fmt.Errorf("waiting for ts-es to be ready: %w", err)
					}
					log.Printf("All nodes are ready in %s", time.Since(ready))

					return nil
				},
				AfterStep: func() error {
					if joinNNodesArgs.MemoryHeapProfilePath != "" {
						f, err := os.Create(joinNNodesArgs.MemoryHeapProfilePath)
						if err != nil {
							return err
						}
						pprof.WriteHeapProfile(f)
						f.Close()
					}

					return nil
				},
			},
		},
		TearDown: func() error {
			log.Printf("Tearing down scenario")
			// Use a new context here to be able to clean up the nodes if the
			// main context is canceled.
			ctx := context.Background()

			if dir := joinNNodesArgs.OutputDir; dir != "" {
				if _, err := os.Stat(dir); os.IsNotExist(err) {
					err = os.MkdirAll(dir, 0755)
					if err != nil {
						return fmt.Errorf("creating output directory: %w", err)
					}
				}
				p := path.Join(joinNNodesArgs.OutputDir, fmt.Sprintf("join-n-nodes-%d-%s.json", joinNNodesArgs.Count, time.Now().Format(TimeFileNameFormat)))
				nm.SaveStatusToFile(p)
			}

			return nm.CloseAndDeleteAll(ctx, chaos)
		},
	}

	return s.Run()
}
