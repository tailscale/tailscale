// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package tswgbench

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tailscale.com/ipn/ipnstate"
)

// The subnet router benchmark's tailscaled modes run real tailscaled (built
// from this tree) on the router and the clients, rather than bare tunnels,
// with a self-contained control plane (./benchcontrol) on the backend:
//
//	tskernel  the router's tailscaled uses the tswg kernel data plane
//	          (TS_DEBUG_TSWG=1)
//	tstun     the router's tailscaled uses TUN and wireguard-go
//
// The clients' tailscaled uses the kernel data plane, unless
// TSWG_SUBNET_CLIENT_MODE is wggo. The router advertises the backend's
// address as a subnet route (with tailscaled's default SNAT), and the
// clients accept it.
const (
	modeTSKernel = "tskernel"
	modeTSTUN    = "tstun"

	tsSocket   = "/run/tswgbench-ts.sock"
	tsStateDir = "/var/lib/tswgbench-ts"
	tsUnit     = "tswgbench-tailscaled"
	ctlPort    = 9911
)

func isTailscaledMode(mode string) bool { return mode == modeTSKernel || mode == modeTSTUN }

var tsArtifacts struct {
	once                  sync.Once
	err                   error
	tailscaled, tailscale []byte
	control               []byte
	tswgctl               []byte // for debugging
}

// buildTailscaled builds tailscaled, the tailscale CLI and benchcontrol for
// the remote hosts.
func buildTailscaled(tmp string) error {
	tsArtifacts.once.Do(func() {
		tsArtifacts.err = func() error {
			for _, b := range []struct {
				pkg string
				out *[]byte
			}{
				{"tailscale.com/cmd/tailscaled", &tsArtifacts.tailscaled},
				{"tailscale.com/cmd/tailscale", &tsArtifacts.tailscale},
				{"tailscale.com/tstest/tswgbench/benchcontrol", &tsArtifacts.control},
				{"tailscale.com/cmd/tswgctl", &tsArtifacts.tswgctl},
			} {
				path := filepath.Join(tmp, filepath.Base(b.pkg))
				cmd := exec.Command("go", "build", "-o", path, b.pkg)
				cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
				if out, err := cmd.CombinedOutput(); err != nil {
					return fmt.Errorf("building %s: %v\n%s", b.pkg, err, out)
				}
				var err error
				if *b.out, err = os.ReadFile(path); err != nil {
					return err
				}
			}
			return nil
		}()
	})
	return tsArtifacts.err
}

// tsState is the tailscaled setup of a subnetLab.
type tsState struct {
	installed    bool
	running      bool   // tailscaled up on the router and clients
	routerKernel bool   // the router's tailscaled uses the kernel data plane
	routerIP     string // the router's Tailscale IPv4 address
}

// ts runs the tailscale CLI on h with args, returning its output.
func tsCLI(h *remoteHost, args string) (string, error) {
	return h.ssh("sudo ~/tailscale --socket="+tsSocket+" "+args, nil)
}

// installTailscaled copies the binaries to the hosts, starts benchcontrol
// on the backend, and loads tswg on the router and clients.
func (s *subnetLab) installTailscaled() {
	t := s.lb.t
	if err := buildTailscaled(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, len(s.lb.vms))
	for i, v := range s.lb.vms {
		wg.Go(func() {
			errs[i] = func() error {
				h := v.host
				files := map[string][]byte{
					"tailscaled": tsArtifacts.tailscaled,
					"tailscale":  tsArtifacts.tailscale,
					"tswgctl":    tsArtifacts.tswgctl,
				}
				if v == s.backend {
					files = map[string][]byte{"benchcontrol": tsArtifacts.control}
				}
				for name, b := range files {
					if _, err := h.ssh(fmt.Sprintf("cat > ~/%s.new && chmod +x ~/%s.new && mv ~/%s.new ~/%s", name, name, name, name), b); err != nil {
						return err
					}
				}
				if v == s.backend {
					_, err := h.ssh(fmt.Sprintf(`
sudo systemctl stop tswgbench-control 2>/dev/null || true
sudo systemctl reset-failed tswgbench-control 2>/dev/null || true
sudo systemd-run --quiet --unit=tswgbench-control --collect "$HOME/benchcontrol" --addr=%s
`, netip.AddrPortFrom(s.backend.under4, ctlPort)), nil)
					return err
				}
				// tswg's dependencies are modules on Ubuntu; the agent
				// may have loaded tswg already.
				_, err := h.ssh(`
sudo systemctl stop `+tsUnit+` 2>/dev/null || true
sudo systemctl reset-failed `+tsUnit+` 2>/dev/null || true
sudo modprobe -a udp_tunnel ip6_udp_tunnel libcurve25519 2>/dev/null || true
lsmod | grep -q '^tswg ' || sudo insmod /tswg.ko
sudo rm -rf `+tsStateDir, nil)
				return err
			}()
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("installing tailscaled on VM %d: %v", i, err)
		}
	}
	t.Cleanup(func() {
		for _, v := range s.lb.vms {
			if v == s.backend {
				v.host.ssh("sudo systemctl stop tswgbench-control 2>/dev/null || true", nil)
			} else {
				v.host.ssh("sudo systemctl stop "+tsUnit+" 2>/dev/null || true", nil)
			}
		}
	})
	s.ts.installed = true
}

// startTailscaled (re)starts tailscaled on h, with the kernel data plane
// if kernel, and brings it up with extra args for tailscale up.
func (s *subnetLab) startTailscaled(h *remoteHost, kernel bool, upArgs string) error {
	env := ""
	if kernel {
		env = "--setenv=TS_DEBUG_TSWG=1"
	}
	_, err := h.ssh(fmt.Sprintf(`
set -e
sudo systemctl stop %[1]s 2>/dev/null || true
sudo systemctl reset-failed %[1]s 2>/dev/null || true
sudo systemd-run --quiet --unit=%[1]s --collect %[2]s --setenv=TS_NO_LOGS_NO_SUPPORT=true \
	--setenv=TS_PANIC_IF_HIT_MAIN_CONTROL=1 --setenv=TS_DISABLE_PORTMAPPER=1 \
	"$HOME/tailscaled" --statedir=%[3]s --socket=%[4]s --port=41641
for i in $(seq 50); do [ -S %[4]s ] && break; sleep 0.1; done
`, tsUnit, env, tsStateDir, tsSocket), nil)
	if err != nil {
		return err
	}
	_, err = tsCLI(h, fmt.Sprintf("up --login-server=http://%s --hostname=%s --timeout=60s %s",
		netip.AddrPortFrom(s.backend.under4, ctlPort), h.Name, upArgs))
	return err
}

// tsStatus returns h's tailscale status.
func tsStatus(h *remoteHost) (*ipnstate.Status, error) {
	out, err := tsCLI(h, "status --json")
	if err != nil {
		return nil, err
	}
	st := new(ipnstate.Status)
	if err := json.Unmarshal([]byte(out), st); err != nil {
		return nil, err
	}
	return st, nil
}

// setupTailscaled sets up the tailscaled modes: tailscaled running on the
// router (with the kernel data plane if kernel) and the clients, all with
// direct paths, and the clients routing the backend over Tailscale.
func (s *subnetLab) setupTailscaled(kernel bool) {
	t := s.lb.t
	if !s.ts.installed {
		s.installTailscaled()
	}
	backendRoute := netip.PrefixFrom(s.backend.under4, 32).String()
	if !s.ts.running || s.ts.routerKernel != kernel {
		if err := s.startTailscaled(s.router.host, kernel,
			"--advertise-routes="+backendRoute+" --snat-subnet-routes=true"); err != nil {
			t.Fatalf("starting the router's tailscaled: %v", err)
		}
		s.ts.routerKernel = kernel
		st, err := tsStatus(s.router.host)
		if err != nil || len(st.Self.TailscaleIPs) == 0 {
			t.Fatalf("router status: %v", err)
		}
		s.ts.routerIP = st.Self.TailscaleIPs[0].String()
	}
	if !s.ts.running {
		var wg sync.WaitGroup
		errs := make([]error, len(s.clients))
		for i, c := range s.clients {
			wg.Go(func() {
				errs[i] = s.startTailscaled(c.host, s.clientMode != modeWGGo, "--accept-routes")
			})
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("starting client %d's tailscaled: %v", i, err)
			}
		}
		s.ts.running = true
	}
	// Wait for every client to have the route, a direct path to the
	// router (not DERP), and a working TCP connection to the backend's
	// benchmark port through it (the OS routes lag tailscale status).
	deadline := time.Now().Add(2 * time.Minute)
	tcpCheck := fmt.Sprintf("ip route get %s | grep -q tailscale0 && timeout 2 bash -c 'echo > /dev/tcp/%s/%d'",
		s.backend.under4, s.backend.under4, benchPort)
	for _, c := range s.clients {
		for {
			why := func() string {
				out, err := tsCLI(c.host, "ping --c=1 --timeout=3s "+s.ts.routerIP)
				if err != nil || !strings.Contains(out, " via ") || strings.Contains(out, "DERP") {
					return fmt.Sprintf("no direct path to the router: %v: %s", err, out)
				}
				st, err := tsStatus(c.host)
				if err != nil {
					return fmt.Sprintf("status: %v", err)
				}
				if !hasRoute(st, s.backend.under4) {
					return "no route to the backend in tailscale status"
				}
				if out, err := c.host.ssh(tcpCheck+" || { ip route get "+s.backend.under4.String()+"; false; }", nil); err != nil {
					return fmt.Sprintf("TCP to the backend: %v: %s", err, out)
				}
				return ""
			}()
			if why == "" {
				break
			}
			if time.Now().After(deadline) {
				diag, _ := c.host.ssh(fmt.Sprintf(`
echo "== route"; ip route get %[1]s
echo "== rules"; ip rule
echo "== table 52"; ip route show table 52
echo "== tswg"; lsmod | grep tswg; ip -d link show tailscale0 | head -3
echo "== status"; sudo ~/tailscale --socket=%[2]s status
echo "== device"; sudo ~/tswgctl show tailscale0 | python3 -c 'import json,sys; d=json.load(sys.stdin); print({k: v for k, v in d.items() if k != "Peers"}, len(d.get("Peers") or []), "peers")'
echo "== dmesg"; sudo dmesg | tail -8
echo "== log"; sudo journalctl -u %[3]s --no-pager | grep -iE "tswg|kernel|socket|error" | tail -20
`, s.backend.under4, tsSocket, tsUnit), nil)
				// The two ends' kernel peer entries for each other.
				peerOf := `python3 -c 'import json,sys; d=json.load(sys.stdin); [print(json.dumps({k: p.get(k) for k in ("PublicKey","Endpoint","LastHandshake","RxBytes","TxBytes","AllowedIPs","NoRoam")})) for p in d.get("Peers") or [] if any(a.startswith(sys.argv[1]+"/") for a in p.get("AllowedIPs") or [])]' `
				cst, _ := tsStatus(c.host)
				var cIP string
				if cst != nil && len(cst.Self.TailscaleIPs) > 0 {
					cIP = cst.Self.TailscaleIPs[0].String()
				}
				cside, _ := c.host.ssh("sudo ~/tswgctl show tailscale0 | "+peerOf+s.ts.routerIP, nil)
				rside, _ := s.router.host.ssh("sudo ~/tswgctl show tailscale0 | "+peerOf+cIP, nil)
				t.Fatalf("client %s not ready: %s\n%s\n== client's kernel peer for the router:\n%s\n== router's kernel peer for the client (%s):\n%s",
					c.host.Name, why, diag, cside, cIP, rside)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// hasRoute reports whether some peer in st offers a route to ip.
func hasRoute(st *ipnstate.Status, ip netip.Addr) bool {
	for _, p := range st.Peer {
		if p.PrimaryRoutes == nil {
			continue
		}
		for _, r := range p.PrimaryRoutes.All() {
			if r.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// stopTailscaled stops tailscaled on the router and clients, so that its
// routes don't capture the bare tunnels' traffic.
func (s *subnetLab) stopTailscaled() {
	if !s.ts.running {
		return
	}
	var wg sync.WaitGroup
	for _, v := range append([]*vm{s.router}, s.clients...) {
		wg.Go(func() {
			v.host.ssh("sudo systemctl stop "+tsUnit+" 2>/dev/null || true", nil)
		})
	}
	wg.Wait()
	s.ts.running = false
}
