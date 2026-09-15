// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"
	"time"

	"go.uber.org/zap"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"tailscale.com/tstest/integration"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

const (
	// controlTunnelPort is the port on the in-cluster ssh-server Service that is tunnelled to the control server
	// on the host, both for devcontrol and for the spike's test control server.
	controlTunnelPort = 31544
	// derpTunnelPort is the port on the ssh-server Service that the spike tunnels to a DERP server on the host.
	derpTunnelPort = 31545
)

var (
	// ciliumSpike is true when the harness runs in --cilium-spike mode.
	ciliumSpike bool
	// spikeControl is the test control server the spike's tailscaled instances register with.
	spikeControl *testcontrol.Server
	// builtTailscaleImage is the tailscale image built by --build, for workloads the tests deploy directly.
	builtTailscaleImage string
)

// setupCiliumSpike starts a test control server and a DERP server in the test process, makes them reachable from
// the cluster through the same reverse SSH tunnel devcontrol uses, sets clusterLoginServer accordingly, and keeps
// approving the subnet routes that nodes advertise. It returns a cleanup function.
func setupCiliumSpike(ctx context.Context, logger *zap.SugaredLogger, restCfg *rest.Config, cl client.WithWatch) (cleanup func(), err error) {
	privateKey, publicKey, err := readOrGenerateSSHKey(tmp)
	if err != nil {
		return nil, fmt.Errorf("failed to read or generate SSH key: %w", err)
	}

	logger.Info("Setting up SSH reverse tunnels from cluster to the test control server...")
	sshServiceIP, err := applySSHResources(ctx, cl, "3.21", publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to apply ssh-server resources: %w", err)
	}
	sshPodName, err := waitForPodReady(ctx, logger, cl, ns, client.MatchingLabels{"app": "ssh-server"})
	if err != nil {
		return nil, fmt.Errorf("ssh-server Pod not ready: %w", err)
	}
	if err := forwardLocalPortToPod(ctx, logger, restCfg, ns, sshPodName, 8022); err != nil {
		return nil, fmt.Errorf("failed to set up port forwarding to ssh-server: %w", err)
	}

	// The DERP server is the bootstrap path for the tailscaled instances; the nodes connect directly through the
	// cluster network afterwards. There is no STUN: it is UDP, which the tunnel cannot carry, and nodes learn
	// their endpoints from their interfaces anyway.
	derpMap := integration.RunDERPAndSTUN(fakeTB{}, logger.Infof, "127.0.0.1")
	var localDERPPort int
	for _, region := range derpMap.Regions {
		for _, node := range region.Nodes {
			localDERPPort = node.DERPPort
			node.HostName = sshServiceIP
			node.IPv4 = sshServiceIP
			node.IPv6 = "none"
			node.DERPPort = derpTunnelPort
			node.STUNPort = -1
			node.InsecureForTests = true
		}
	}
	if localDERPPort == 0 {
		return nil, errors.New("no DERP node in the test DERP map")
	}

	// Must be a private IP so that clients don't try an HTTPS fallback; see clusterLoginServer for devcontrol.
	clusterLoginServer = "http://" + net.JoinHostPort(sshServiceIP, fmt.Sprint(controlTunnelPort))
	spikeControl = &testcontrol.Server{
		Logf:            logger.Named("testcontrol").Debugf,
		DERPMap:         derpMap,
		ExplicitBaseURL: clusterLoginServer,
	}
	localControlAddr := fmt.Sprintf("127.0.0.1:%d", controlTunnelPort)
	ln, err := net.Listen("tcp", localControlAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for the test control server on %s: %w", localControlAddr, err)
	}
	srv := &http.Server{Handler: spikeControl}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Errorf("test control server: %v", err)
		}
	}()

	if err := reverseTunnel(ctx, logger, privateKey, "localhost:8022", controlTunnelPort, localControlAddr); err != nil {
		return nil, fmt.Errorf("failed to set up the control reverse tunnel: %w", err)
	}
	if err := reverseTunnel(ctx, logger, privateKey, "localhost:8022", derpTunnelPort, fmt.Sprintf("127.0.0.1:%d", localDERPPort)); err != nil {
		return nil, fmt.Errorf("failed to set up the DERP reverse tunnel: %w", err)
	}
	logger.Infof("test control server reachable from the cluster at %s, DERP at %s:%d", clusterLoginServer, sshServiceIP, derpTunnelPort)

	approveCtx, stopApproving := context.WithCancel(ctx)
	go approveAdvertisedRoutes(approveCtx, logger, spikeControl)

	return func() {
		stopApproving()
		srv.Close()
		if err := cleanupSSHResources(context.Background(), cl); err != nil {
			logger.Infof("failed to clean up ssh-server resources: %v", err)
		}
	}, nil
}

// approveAdvertisedRoutes emulates a tailnet with auto-approved routes: the test control server does not read the
// routes nodes advertise, so every advertised route is approved for the node that advertises it.
func approveAdvertisedRoutes(ctx context.Context, logger *zap.SugaredLogger, control *testcontrol.Server) {
	approved := map[key.NodePublic][]netip.Prefix{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		for _, n := range control.AllNodes() {
			if !n.Hostinfo.Valid() {
				continue
			}
			routes := n.Hostinfo.RoutableIPs().AsSlice()
			if len(routes) == 0 || slices.Equal(approved[n.Key], routes) {
				continue
			}
			logger.Infof("approving routes %v advertised by %s", routes, n.Name)
			control.SetSubnetRoutes(n.Key, routes)
			approved[n.Key] = routes
		}
	}
}

// fakeTB satisfies testing.TB for integration.RunDERPAndSTUN outside a test, as cmd/testcontrol does. The DERP
// server lives for the rest of the process. Methods not overridden here are promoted from the nil *testing.T and
// must not be called.
type fakeTB struct {
	*testing.T
}

func (t fakeTB) Cleanup(_ func())                  {}
func (t fakeTB) Error(args ...any)                 { log.Fatal(args...) }
func (t fakeTB) Errorf(format string, args ...any) { log.Fatalf(format, args...) }
func (t fakeTB) Fail()                             { log.Fatal("failed") }
func (t fakeTB) FailNow()                          { log.Fatal("failed") }
func (t fakeTB) Failed() bool                      { return false }
func (t fakeTB) Fatal(args ...any)                 { log.Fatal(args...) }
func (t fakeTB) Fatalf(format string, args ...any) { log.Fatalf(format, args...) }
func (t fakeTB) Helper()                           {}
func (t fakeTB) Log(args ...any)                   { log.Print(args...) }
func (t fakeTB) Logf(format string, args ...any)   { log.Printf(format, args...) }
func (t fakeTB) Name() string                      { return "cilium-spike" }
func (t fakeTB) Setenv(key string, value string)   { panic("not implemented") }
func (t fakeTB) Skip(args ...any)                  { log.Fatal("skipped") }
func (t fakeTB) SkipNow()                          { log.Fatal("skipnow") }
func (t fakeTB) Skipf(format string, args ...any)  { log.Fatalf(format, args...) }
func (t fakeTB) Skipped() bool                     { return false }
func (t fakeTB) TempDir() string                   { panic("not implemented") }
func (t fakeTB) Context() context.Context          { return context.Background() }
func (t fakeTB) Output() io.Writer                 { return io.Discard }
