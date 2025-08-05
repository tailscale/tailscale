package chaos

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	xmaps "golang.org/x/exp/maps"
	"golang.org/x/sync/semaphore"
	"tailscale.com/client/tailscale/v2"
)

var ciChurnArgs struct {
	Verbose         int           `flag:"verbose,default=0,Print verbose output, 0: no, 1: yes, 2: very verbose"`
	JoinTimeout     time.Duration `flag:"join-timeout,default=30s,Timeout for a node joining the tailnet"`
	JoinParallelism int           `flag:"join-parallelism,default=150,Number of nodes to join in parallel"`
	NodeType        string        `flag:"node-type,default=direct,Type of node to create, one of: direct (lightweight) or tsnet (full)"`
}

var ciChurnCmd = &command.C{
	Name: "ci-churn",
	Help: `Join a set of service nodes and a set of high Churn CI nodes to a tailscale network.`,

	Run:      command.Adapt(runCIChurn),
	SetFlags: command.Flags(flax.MustBind, &ciChurnArgs),
}

func runCIChurn(env *command.Env) error {
	tc, err := NewControl(baseArgs.LoginServer, baseArgs.Tailnet, baseArgs.ApiKey)
	if err != nil {
		return err
	}

	chaos := NewChaos(tc)

	if baseArgs.ApiKey == "" {
		return fmt.Errorf("--apikey is required")
	}

	type taggedNodesSpec struct {
		opts    NodeOpts
		count   int
		newFunc NewNodeFunc
	}

	jobSpec := func(c int, eph bool) taggedNodesSpec {
		o := NodeOpts{
			loginServer: baseArgs.LoginServer,
			ephemeral:   eph,
		}
		setVerboseOptionsFromFlag(&o, ciChurnArgs.Verbose)
		return taggedNodesSpec{
			count:   c,
			opts:    o,
			newFunc: NewNodeDirectAsync,
		}
	}

	// 100 admins that can access anything
	userSpec := map[string]taggedNodesSpec{
		"tag:user-admins": jobSpec(100, false),
	}
	// 100 groups of developers that can access their own services,
	// 3 devices per group.
	const numDevs = 100
	for i := range numDevs {
		userSpec[fmt.Sprintf("tag:user-dev%d", i)] = jobSpec(3, false)
	}

	commonTaggedSpec := map[string]taggedNodesSpec{}
	// 100 common services that can be accessed from all CI jobs.
	for i := range 100 {
		commonTaggedSpec[fmt.Sprintf("tag:svc-common%d", i)] = jobSpec(3, false)
	}
	appTaggedSpec := map[string]taggedNodesSpec{}
	// 300 app-specific services that can be accessed from app-specific CI jobs.
	const numApps = 300
	for i := range numApps {
		appTaggedSpec[fmt.Sprintf("tag:svc-app%d", i)] = jobSpec(3, false)
	}

	ciSpec := map[string]taggedNodesSpec{
		// 4100 nodes in the common CI pool.
		"tag:ci-common": jobSpec(4100, true),
	}
	// 300 app-specific CI services.
	for i := range numApps {
		ciSpec[fmt.Sprintf("tag:ci-app%d", i)] = jobSpec(3, true)
	}

	s := Scenario{
		BeforeSteps: func() error {
			if baseArgs.RemoveAll {
				if err := chaos.RemoveAllNodes(env); err != nil {
					return fmt.Errorf("removing all nodes: %w", err)
				}
			}

			// TODO: can make this read by CLI
			o := []string{"insecure@example.com"}
			allTags := append(append(append(xmaps.Keys(userSpec), xmaps.Keys(commonTaggedSpec)...), xmaps.Keys(ciSpec)...), xmaps.Keys(appTaggedSpec)...)
			pol := tailscale.ACL{
				TagOwners: tagsToTagOwners(o, allTags),
				ACLs: []tailscale.ACLEntry{
					{
						// Admins can access everything.
						Action:      "accept",
						Source:      []string{"tag:user-admins"},
						Destination: []string{"*:22", "*:80", "*:443"},
					},
					{
						// All CI jobs can access common tagged services.
						Action:      "accept",
						Source:      xmaps.Keys(ciSpec),
						Destination: tagsToDst(xmaps.Keys(commonTaggedSpec), "80"),
					},
				},
			}
			for i := range numApps {
				pol.ACLs = append(pol.ACLs, tailscale.ACLEntry{
					// App-specific CI jobs can access app-specific services.
					Action:      "accept",
					Source:      []string{fmt.Sprintf("tag:ci-app%d", i)},
					Destination: []string{fmt.Sprintf("tag:svc-app%d:80", i)},
				})
			}
			for i := range numDevs {
				pol.ACLs = append(pol.ACLs, tailscale.ACLEntry{
					// Developers can access their services
					Action: "accept",
					Source: []string{fmt.Sprintf("tag:user-dev%d", i)},
					Destination: []string{
						fmt.Sprintf("tag:svc-app%d:80", i),
						fmt.Sprintf("tag:svc-app%d:80", 100+i),
						fmt.Sprintf("tag:svc-app%d:80", 200+i),
					},
				})
			}
			ctx, cancel := context.WithTimeout(env.Context(), 10*time.Second)
			defer cancel()

			if _, err := chaos.SetACL(ctx, pol); err != nil {
				return err
			}

			return nil
		},
		Steps: []Step{
			{Run: func() error {
				parallelismSem := semaphore.NewWeighted(int64(ciChurnArgs.JoinParallelism))
				var wg sync.WaitGroup

				// CI services.
				ciTicker := newJitteredTicker(env.Context(), 3*time.Minute, time.Second/20)
				for tag, spec := range ciSpec {
					wg.Add(1)
					go func() {
						defer wg.Done()
						NodeGroupSimulator(env.Context(), chaos, spec.opts, tag, spec.count, parallelismSem, ciTicker)
					}()
				}

				// Tagged services, churning every 30 min.
				taggedTicker := newJitteredTicker(env.Context(), 3*time.Minute, 30*time.Minute)
				for tag, spec := range commonTaggedSpec {
					wg.Add(1)
					go func() {
						defer wg.Done()
						NodeGroupSimulator(env.Context(), chaos, spec.opts, tag, spec.count, parallelismSem, taggedTicker)
					}()
				}
				for tag, spec := range appTaggedSpec {
					wg.Add(1)
					go func() {
						defer wg.Done()
						NodeGroupSimulator(env.Context(), chaos, spec.opts, tag, spec.count, parallelismSem, taggedTicker)
					}()
				}

				// User nodes, churning every 1hr.
				userTicker := newJitteredTicker(env.Context(), 3*time.Minute, 1*time.Hour)
				for tag, spec := range userSpec {
					wg.Add(1)
					go func() {
						defer wg.Done()
						NodeGroupSimulator(env.Context(), chaos, spec.opts, tag, spec.count, parallelismSem, userTicker)
					}()
				}

				wg.Wait()
				return nil
			}},
		},
		TearDown: func() error {
			log.Printf("Tearing down scenario")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := chaos.removeAllNodes(ctx); err != nil {
				return fmt.Errorf("removing all nodes: %w", err)
			}
			return nil
		},
	}

	err = s.Run()
	if err != nil {
		log.Printf("Error running scenario: %v", err)
		return err
	}
	return nil
}

// NodeGroupSimulator simulates a group of nodes joining and leaving a network.
// When a node joins the network, it will join with a tag and an authkey.
// The node will then leave the network after a random amount of time.
// A new node will join the network for a new random amount of time.
// TODO(kradalby): rename
func NodeGroupSimulator(ctx context.Context, chaos *Chaos, opts NodeOpts, tag string, c int, parallelismSem *semaphore.Weighted, stop jticker) {
	sem := semaphore.NewWeighted(int64(c))

	key, err := chaos.Control.CreatAuthKey(ctx, opts.ephemeral, []string{tag})
	if err != nil {
		log.Printf("failed to create authkey: %s", err)
		errCount.WithLabelValues("authkey").Inc()
		return
	}
	opts.authKey = key
	opts.tags = []string{tag}

	for {
		if err := sem.Acquire(ctx, 1); err != nil {
			log.Printf("failed to acquire semaphore: %v", err)
			return
		}
		if err := parallelismSem.Acquire(ctx, 1); err != nil {
			log.Printf("failed to acquire parallelism semaphore: %v", err)
			return
		}

		go func() {
			defer sem.Release(1)
			err := NewLimitedLifetimeNode(ctx, nodeFuncFromFlag(ciChurnArgs.NodeType), func() {
				parallelismSem.Release(1)
			}, opts, stop)
			if err != nil {
				log.Printf("error creating limited lifetime node: %v", err)
				errCount.WithLabelValues("createnode").Inc()
			}
		}()
	}
}

// NewLimitedLifetimeNode creates a new node, starts it, waits for it to be running,
// and then closes it after the given lifetime.
// The node is created using the given NewNodeFunc.
// This function should be spawned in a go routine, it is closed by declaring the context Done.
func NewLimitedLifetimeNode(ctx context.Context, newFunc NewNodeFunc, loginDoneFunc func(), opts NodeOpts, stop jticker) error {
	pending := newFunc(ctx, opts)
	node, ok := <-pending
	if !ok {
		loginDoneFunc()
		return fmt.Errorf("failed to create node")
	}

	err := node.Start(ctx)
	if err != nil {
		loginDoneFunc()
		return fmt.Errorf("failed to start node: %w", err)
	}

	loginDoneFunc()

	err = node.WaitRunning(ctx)
	if err != nil {
		return fmt.Errorf("failed to wait for node to be running: %w", err)
	}

	select {
	case <-stop:
	case <-ctx.Done():
	}

	closeCtx, close := context.WithTimeout(context.Background(), 30*time.Second)
	defer close()
	err = node.Close(closeCtx)
	if err != nil {
		return fmt.Errorf("failed to close node: %w", err)
	}

	return nil
}
