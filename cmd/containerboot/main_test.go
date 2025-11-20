// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux

package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
	"tailscale.com/ipn"
	"tailscale.com/kube/egressservices"
	"tailscale.com/kube/kubeclient"
	"tailscale.com/kube/kubetypes"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/netmap"
	"tailscale.com/types/ptr"
)

func TestContainerBoot(t *testing.T) {
	boot := filepath.Join(t.TempDir(), "containerboot")
	if err := exec.Command("go", "build", "-ldflags", "-X main.testSleepDuration=1ms", "-o", boot, "tailscale.com/cmd/containerboot").Run(); err != nil {
		t.Fatalf("Building containerboot: %v", err)
	}
	egressStatus := egressSvcStatus("foo", "foo.tailnetxyz.ts.net")

	metricsURL := func(port int) string {
		return fmt.Sprintf("http://127.0.0.1:%d/metrics", port)
	}
	healthURL := func(port int) string {
		return fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	}
	egressSvcTerminateURL := func(port int) string {
		return fmt.Sprintf("http://127.0.0.1:%d%s", port, kubetypes.EgessServicesPreshutdownEP)
	}

	capver := fmt.Sprintf("%d", tailcfg.CurrentCapabilityVersion)

	type phase struct {
		// If non-nil, send this IPN bus notification (and remember it as the
		// initial update for any future new watchers, then wait for all the
		// Waits below to be true before proceeding to the next phase.
		Notify *ipn.Notify

		// WantCmds is the commands that containerboot should run in this phase.
		WantCmds []string

		// WantKubeSecret is the secret keys/values that should exist in the
		// kube secret.
		WantKubeSecret map[string]string

		// Update the kube secret with these keys/values at the beginning of the
		// phase (simulates our fake tailscaled doing it).
		UpdateKubeSecret map[string]string

		// WantFiles files that should exist in the container and their
		// contents.
		WantFiles map[string]string

		// WantLog is a log message we expect from containerboot.
		WantLog string

		// If set for a phase, the test will expect containerboot to exit with
		// this error code, and the test will finish on that phase without
		// waiting for the successful startup log message.
		WantExitCode *int

		// The signal to send to containerboot at the start of the phase.
		Signal *syscall.Signal

		EndpointStatuses map[string]int
	}
	runningNotify := &ipn.Notify{
		State: ptr.To(ipn.Running),
		NetMap: &netmap.NetworkMap{
			SelfNode: (&tailcfg.Node{
				StableID:  tailcfg.StableNodeID("myID"),
				Name:      "test-node.test.ts.net",
				Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
			}).View(),
		},
	}
	type testCase struct {
		Env           map[string]string
		KubeSecret    map[string]string
		KubeDenyPatch bool
		Phases        []phase
	}
	tests := map[string]func(env *testEnv) testCase{
		"no_args": func(env *testEnv) testCase {
			return testCase{
				// Out of the box default: runs in userspace mode, ephemeral storage, interactive login.
				Env: nil,
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false",
						},
						// No metrics or health by default.
						EndpointStatuses: map[string]int{
							metricsURL(9002): -1,
							healthURL(9002):  -1,
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"authkey": func(env *testEnv) testCase {
			return testCase{
				// Userspace mode, ephemeral storage, authkey provided on every run.
				Env: map[string]string{
					"TS_AUTHKEY": "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"authkey_old_flag": func(env *testEnv) testCase {
			return testCase{
				// Userspace mode, ephemeral storage, authkey provided on every run.
				Env: map[string]string{
					"TS_AUTH_KEY": "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"authkey_disk_state": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":   "tskey-key",
					"TS_STATE_DIR": filepath.Join(env.d, "tmp"),
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"routes": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY": "tskey-key",
					"TS_ROUTES":  "1.2.3.0/24,10.20.30.0/24",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key --advertise-routes=1.2.3.0/24,10.20.30.0/24",
						},
					},
					{
						Notify: runningNotify,
						WantFiles: map[string]string{
							"proc/sys/net/ipv4/ip_forward":          "0",
							"proc/sys/net/ipv6/conf/all/forwarding": "0",
						},
					},
				},
			}
		},
		"empty_routes": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY": "tskey-key",
					"TS_ROUTES":  "",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key --advertise-routes=",
						},
					},
					{
						Notify: runningNotify,
						WantFiles: map[string]string{
							"proc/sys/net/ipv4/ip_forward":          "0",
							"proc/sys/net/ipv6/conf/all/forwarding": "0",
						},
					},
				},
			}
		},
		"routes_kernel_ipv4": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":   "tskey-key",
					"TS_ROUTES":    "1.2.3.0/24,10.20.30.0/24",
					"TS_USERSPACE": "false",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key --advertise-routes=1.2.3.0/24,10.20.30.0/24",
						},
					},
					{
						Notify: runningNotify,
						WantFiles: map[string]string{
							"proc/sys/net/ipv4/ip_forward":          "1",
							"proc/sys/net/ipv6/conf/all/forwarding": "0",
						},
					},
				},
			}
		},
		"routes_kernel_ipv6": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":   "tskey-key",
					"TS_ROUTES":    "::/64,1::/64",
					"TS_USERSPACE": "false",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key --advertise-routes=::/64,1::/64",
						},
					},
					{
						Notify: runningNotify,
						WantFiles: map[string]string{
							"proc/sys/net/ipv4/ip_forward":          "0",
							"proc/sys/net/ipv6/conf/all/forwarding": "1",
						},
					},
				},
			}
		},
		"routes_kernel_all_families": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":   "tskey-key",
					"TS_ROUTES":    "::/64,1.2.3.0/24",
					"TS_USERSPACE": "false",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key --advertise-routes=::/64,1.2.3.0/24",
						},
					},
					{
						Notify: runningNotify,
						WantFiles: map[string]string{
							"proc/sys/net/ipv4/ip_forward":          "1",
							"proc/sys/net/ipv6/conf/all/forwarding": "1",
						},
					},
				},
			}
		},
		"ingress_proxy": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":   "tskey-key",
					"TS_DEST_IP":   "1.2.3.4",
					"TS_USERSPACE": "false",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"egress_proxy": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":           "tskey-key",
					"TS_TAILNET_TARGET_IP": "100.99.99.99",
					"TS_USERSPACE":         "false",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantFiles: map[string]string{
							"proc/sys/net/ipv4/ip_forward":          "1",
							"proc/sys/net/ipv6/conf/all/forwarding": "0",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"egress_proxy_fqdn_ipv6_target_on_ipv4_host": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":               "tskey-key",
					"TS_TAILNET_TARGET_FQDN":   "ipv6-node.test.ts.net", // resolves to IPv6 address
					"TS_USERSPACE":             "false",
					"TS_TEST_FAKE_NETFILTER_6": "false",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantFiles: map[string]string{
							"proc/sys/net/ipv4/ip_forward":          "1",
							"proc/sys/net/ipv6/conf/all/forwarding": "0",
						},
					},
					{
						Notify: &ipn.Notify{
							State: ptr.To(ipn.Running),
							NetMap: &netmap.NetworkMap{
								SelfNode: (&tailcfg.Node{
									StableID:  tailcfg.StableNodeID("myID"),
									Name:      "test-node.test.ts.net",
									Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
								}).View(),
								Peers: []tailcfg.NodeView{
									(&tailcfg.Node{
										StableID:  tailcfg.StableNodeID("ipv6ID"),
										Name:      "ipv6-node.test.ts.net",
										Addresses: []netip.Prefix{netip.MustParsePrefix("::1/128")},
									}).View(),
								},
							},
						},
						WantLog:      "no forwarding rules for egress addresses [::1/128], host supports IPv6: false",
						WantExitCode: ptr.To(1),
					},
				},
			}
		},
		"authkey_once": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":   "tskey-key",
					"TS_AUTH_ONCE": "true",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
						},
					},
					{
						Notify: &ipn.Notify{
							State: ptr.To(ipn.NeedsLogin),
						},
						WantCmds: []string{
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
					},
					{
						Notify: runningNotify,
						WantCmds: []string{
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock set --accept-dns=false",
						},
					},
				},
			}
		},
		"auth_key_once_extra_args_override_dns": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_AUTHKEY":    "tskey-key",
					"TS_AUTH_ONCE":  "true",
					"TS_ACCEPT_DNS": "false",
					"TS_EXTRA_ARGS": "--accept-dns",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
						},
					},
					{
						Notify: &ipn.Notify{
							State: ptr.To(ipn.NeedsLogin),
						},
						WantCmds: []string{
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=true --authkey=tskey-key",
						},
					},
					{
						Notify: runningNotify,
						WantCmds: []string{
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock set --accept-dns=true",
						},
					},
				},
			}
		},
		"kube_storage": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
					"POD_UID":                       "some-pod-uid",
				},
				KubeSecret: map[string]string{
					"authkey": "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=kube:tailscale --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							kubetypes.KeyCapVer: capver,
							kubetypes.KeyPodUID: "some-pod-uid",
						},
					},
					{
						Notify: runningNotify,
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							"device_fqdn":       "test-node.test.ts.net",
							"device_id":         "myID",
							"device_ips":        `["100.64.0.1"]`,
							kubetypes.KeyCapVer: capver,
							kubetypes.KeyPodUID: "some-pod-uid",
						},
					},
				},
			}
		},
		"kube_disk_storage": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
					// Explicitly set to an empty value, to override the default of "tailscale".
					"TS_KUBE_SECRET": "",
					"TS_STATE_DIR":   filepath.Join(env.d, "tmp"),
					"TS_AUTHKEY":     "tskey-key",
				},
				KubeSecret: map[string]string{},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{},
					},
					{
						Notify:         runningNotify,
						WantKubeSecret: map[string]string{},
					},
				},
			}
		},
		"kube_storage_no_patch": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
					"TS_AUTHKEY":                    "tskey-key",
				},
				KubeSecret:    map[string]string{},
				KubeDenyPatch: true,
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=kube:tailscale --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{},
					},
					{
						Notify:         runningNotify,
						WantKubeSecret: map[string]string{},
					},
				},
			}
		},
		"kube_storage_auth_once": func(env *testEnv) testCase {
			return testCase{
				// Same as previous, but deletes the authkey from the kube secret.
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
					"TS_AUTH_ONCE":                  "true",
				},
				KubeSecret: map[string]string{
					"authkey": "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=kube:tailscale --statedir=/tmp --tun=userspace-networking",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							kubetypes.KeyCapVer: capver,
						},
					},
					{
						Notify: &ipn.Notify{
							State: ptr.To(ipn.NeedsLogin),
						},
						WantCmds: []string{
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							kubetypes.KeyCapVer: capver,
						},
					},
					{
						Notify: runningNotify,
						WantCmds: []string{
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock set --accept-dns=false",
						},
						WantKubeSecret: map[string]string{
							"device_fqdn":       "test-node.test.ts.net",
							"device_id":         "myID",
							"device_ips":        `["100.64.0.1"]`,
							kubetypes.KeyCapVer: capver,
						},
					},
				},
			}
		},
		"kube_storage_updates": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
				},
				KubeSecret: map[string]string{
					"authkey": "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=kube:tailscale --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							kubetypes.KeyCapVer: capver,
						},
					},
					{
						Notify: runningNotify,
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							"device_fqdn":       "test-node.test.ts.net",
							"device_id":         "myID",
							"device_ips":        `["100.64.0.1"]`,
							kubetypes.KeyCapVer: capver,
						},
					},
					{
						Notify: &ipn.Notify{
							State: ptr.To(ipn.Running),
							NetMap: &netmap.NetworkMap{
								SelfNode: (&tailcfg.Node{
									StableID:  tailcfg.StableNodeID("newID"),
									Name:      "new-name.test.ts.net",
									Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
								}).View(),
							},
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							"device_fqdn":       "new-name.test.ts.net",
							"device_id":         "newID",
							"device_ips":        `["100.64.0.1"]`,
							kubetypes.KeyCapVer: capver,
						},
					},
				},
			}
		},
		"proxies": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_SOCKS5_SERVER":              "localhost:1080",
					"TS_OUTBOUND_HTTP_PROXY_LISTEN": "localhost:8080",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking --socks5-server=localhost:1080 --outbound-http-proxy-listen=localhost:8080",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"dns": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_ACCEPT_DNS": "true",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=true",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"extra_args": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_EXTRA_ARGS":            "--widget=rotated",
					"TS_TAILSCALED_EXTRA_ARGS": "--experiments=widgets",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking --experiments=widgets",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --widget=rotated",
						},
					}, {
						Notify: runningNotify,
					},
				},
			}
		},
		"extra_args_accept_routes": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_EXTRA_ARGS": "--accept-routes",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --accept-routes",
						},
					}, {
						Notify: runningNotify,
					},
				},
			}
		},
		"extra_args_accept_dns": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_EXTRA_ARGS": "--accept-dns",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=true",
						},
					}, {
						Notify: runningNotify,
					},
				},
			}
		},
		"extra_args_accept_dns_overrides_env_var": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_ACCEPT_DNS": "true", // Overridden by TS_EXTRA_ARGS.
					"TS_EXTRA_ARGS": "--accept-dns=false",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false",
						},
					}, {
						Notify: runningNotify,
					},
				},
			}
		},
		"hostname": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_HOSTNAME": "my-server",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --hostname=my-server",
						},
					}, {
						Notify: runningNotify,
					},
				},
			}
		},
		"experimental_tailscaled_config_path": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_EXPERIMENTAL_VERSIONED_CONFIG_DIR": filepath.Join(env.d, "etc/tailscaled/"),
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking --config=/etc/tailscaled/cap-95.hujson",
						},
					}, {
						Notify: runningNotify,
					},
				},
			}
		},
		"metrics_enabled": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_LOCAL_ADDR_PORT": fmt.Sprintf("[::]:%d", env.localAddrPort),
					"TS_ENABLE_METRICS":  "true",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false",
						},
						EndpointStatuses: map[string]int{
							metricsURL(env.localAddrPort): 200,
							healthURL(env.localAddrPort):  -1,
						},
					}, {
						Notify: runningNotify,
					},
				},
			}
		},
		"health_enabled": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_LOCAL_ADDR_PORT":     fmt.Sprintf("[::]:%d", env.localAddrPort),
					"TS_ENABLE_HEALTH_CHECK": "true",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false",
						},
						EndpointStatuses: map[string]int{
							metricsURL(env.localAddrPort): -1,
							healthURL(env.localAddrPort):  503, // Doesn't start passing until the next phase.
						},
					}, {
						Notify: runningNotify,
						EndpointStatuses: map[string]int{
							metricsURL(env.localAddrPort): -1,
							healthURL(env.localAddrPort):  200,
						},
					},
				},
			}
		},
		"metrics_and_health_on_same_port": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_LOCAL_ADDR_PORT":     fmt.Sprintf("[::]:%d", env.localAddrPort),
					"TS_ENABLE_METRICS":      "true",
					"TS_ENABLE_HEALTH_CHECK": "true",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false",
						},
						EndpointStatuses: map[string]int{
							metricsURL(env.localAddrPort): 200,
							healthURL(env.localAddrPort):  503, // Doesn't start passing until the next phase.
						},
					}, {
						Notify: runningNotify,
						EndpointStatuses: map[string]int{
							metricsURL(env.localAddrPort): 200,
							healthURL(env.localAddrPort):  200,
						},
					},
				},
			}
		},
		"local_metrics_and_deprecated_health": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_LOCAL_ADDR_PORT":       fmt.Sprintf("[::]:%d", env.localAddrPort),
					"TS_ENABLE_METRICS":        "true",
					"TS_HEALTHCHECK_ADDR_PORT": fmt.Sprintf("[::]:%d", env.healthAddrPort),
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false",
						},
						EndpointStatuses: map[string]int{
							metricsURL(env.localAddrPort): 200,
							healthURL(env.healthAddrPort): 503, // Doesn't start passing until the next phase.
						},
					}, {
						Notify: runningNotify,
						EndpointStatuses: map[string]int{
							metricsURL(env.localAddrPort): 200,
							healthURL(env.healthAddrPort): 200,
						},
					},
				},
			}
		},
		"serve_config_no_kube": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_SERVE_CONFIG": filepath.Join(env.d, "etc/tailscaled/serve-config.json"),
					"TS_AUTHKEY":      "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=mem: --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
					},
					{
						Notify: runningNotify,
					},
				},
			}
		},
		"serve_config_kube": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
					"TS_SERVE_CONFIG":               filepath.Join(env.d, "etc/tailscaled/serve-config.json"),
				},
				KubeSecret: map[string]string{
					"authkey": "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=kube:tailscale --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							kubetypes.KeyCapVer: capver,
						},
					},
					{
						Notify: runningNotify,
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							"device_fqdn":       "test-node.test.ts.net",
							"device_id":         "myID",
							"device_ips":        `["100.64.0.1"]`,
							"https_endpoint":    "no-https",
							kubetypes.KeyCapVer: capver,
						},
					},
				},
			}
		},
		"egress_svcs_config_kube": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
					"TS_EGRESS_PROXIES_CONFIG_PATH": filepath.Join(env.d, "etc/tailscaled"),
					"TS_LOCAL_ADDR_PORT":            fmt.Sprintf("[::]:%d", env.localAddrPort),
				},
				KubeSecret: map[string]string{
					"authkey": "tskey-key",
				},
				Phases: []phase{
					{
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=kube:tailscale --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							kubetypes.KeyCapVer: capver,
						},
						EndpointStatuses: map[string]int{
							egressSvcTerminateURL(env.localAddrPort): 200,
						},
					},
					{
						Notify: runningNotify,
						WantKubeSecret: map[string]string{
							"egress-services":   string(mustJSON(t, egressStatus)),
							"authkey":           "tskey-key",
							"device_fqdn":       "test-node.test.ts.net",
							"device_id":         "myID",
							"device_ips":        `["100.64.0.1"]`,
							kubetypes.KeyCapVer: capver,
						},
						EndpointStatuses: map[string]int{
							egressSvcTerminateURL(env.localAddrPort): 200,
						},
					},
				},
			}
		},
		"egress_svcs_config_no_kube": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"TS_EGRESS_PROXIES_CONFIG_PATH": filepath.Join(env.d, "etc/tailscaled"),
					"TS_AUTHKEY":                    "tskey-key",
				},
				Phases: []phase{
					{
						WantLog:      "TS_EGRESS_PROXIES_CONFIG_PATH is only supported for Tailscale running on Kubernetes",
						WantExitCode: ptr.To(1),
					},
				},
			}
		},
		"kube_shutdown_during_state_write": func(env *testEnv) testCase {
			return testCase{
				Env: map[string]string{
					"KUBERNETES_SERVICE_HOST":       env.kube.Host,
					"KUBERNETES_SERVICE_PORT_HTTPS": env.kube.Port,
					"TS_ENABLE_HEALTH_CHECK":        "true",
				},
				KubeSecret: map[string]string{
					"authkey": "tskey-key",
				},
				Phases: []phase{
					{
						// Normal startup.
						WantCmds: []string{
							"/usr/bin/tailscaled --socket=/tmp/tailscaled.sock --state=kube:tailscale --statedir=/tmp --tun=userspace-networking",
							"/usr/bin/tailscale --socket=/tmp/tailscaled.sock up --accept-dns=false --authkey=tskey-key",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							kubetypes.KeyCapVer: capver,
						},
					},
					{
						// SIGTERM before state is finished writing, should wait for
						// consistent state before propagating SIGTERM to tailscaled.
						Signal: ptr.To(unix.SIGTERM),
						UpdateKubeSecret: map[string]string{
							"_machinekey":  "foo",
							"_profiles":    "foo",
							"profile-baff": "foo",
							// Missing "_current-profile" key.
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							"_machinekey":       "foo",
							"_profiles":         "foo",
							"profile-baff":      "foo",
							kubetypes.KeyCapVer: capver,
						},
						WantLog: "Waiting for tailscaled to finish writing state to Secret \"tailscale\"",
					},
					{
						// tailscaled has finished writing state, should propagate SIGTERM.
						UpdateKubeSecret: map[string]string{
							"_current-profile": "foo",
						},
						WantKubeSecret: map[string]string{
							"authkey":           "tskey-key",
							"_machinekey":       "foo",
							"_profiles":         "foo",
							"profile-baff":      "foo",
							"_current-profile":  "foo",
							kubetypes.KeyCapVer: capver,
						},
						WantLog:      "HTTP server at [::]:9002 closed",
						WantExitCode: ptr.To(0),
					},
				},
			}
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := newTestEnv(t)
			tc := test(&env)

			for k, v := range tc.KubeSecret {
				env.kube.SetSecret(k, v)
			}
			env.kube.SetPatching(!tc.KubeDenyPatch)

			cmd := exec.Command(boot)
			cmd.Env = []string{
				fmt.Sprintf("PATH=%s/usr/bin:%s", env.d, os.Getenv("PATH")),
				fmt.Sprintf("TS_TEST_RECORD_ARGS=%s", env.argFile),
				fmt.Sprintf("TS_TEST_SOCKET=%s", env.lapi.Path),
				fmt.Sprintf("TS_SOCKET=%s", env.runningSockPath),
				fmt.Sprintf("TS_TEST_ONLY_ROOT=%s", env.d),
				"TS_TEST_FAKE_NETFILTER=true",
			}
			for k, v := range tc.Env {
				cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
			}
			cbOut := &lockingBuffer{}
			defer func() {
				if t.Failed() {
					t.Logf("containerboot output:\n%s", cbOut.String())
				}
			}()
			cmd.Stderr = cbOut
			cmd.Stdout = cbOut
			if err := cmd.Start(); err != nil {
				t.Fatalf("starting containerboot: %v", err)
			}
			defer func() {
				cmd.Process.Signal(unix.SIGTERM)
				cmd.Process.Wait()
			}()

			var wantCmds []string
			for i, p := range tc.Phases {
				for k, v := range p.UpdateKubeSecret {
					env.kube.SetSecret(k, v)
				}
				env.lapi.Notify(p.Notify)
				if p.Signal != nil {
					cmd.Process.Signal(*p.Signal)
				}
				if p.WantLog != "" {
					err := tstest.WaitFor(2*time.Second, func() error {
						waitLogLine(t, time.Second, cbOut, p.WantLog)
						return nil
					})
					if err != nil {
						t.Fatal(err)
					}
				}

				if p.WantExitCode != nil {
					state, err := cmd.Process.Wait()
					if err != nil {
						t.Fatal(err)
					}
					if state.ExitCode() != *p.WantExitCode {
						t.Fatalf("phase %d: want exit code %d, got %d", i, *p.WantExitCode, state.ExitCode())
					}

					// Early test return, we don't expect the successful startup log message.
					return
				}

				wantCmds = append(wantCmds, p.WantCmds...)
				waitArgs(t, 2*time.Second, env.d, env.argFile, strings.Join(wantCmds, "\n"))
				err := tstest.WaitFor(2*time.Second, func() error {
					if p.WantKubeSecret != nil {
						got := env.kube.Secret()
						if diff := cmp.Diff(got, p.WantKubeSecret); diff != "" {
							return fmt.Errorf("unexpected kube secret data (-got+want):\n%s", diff)
						}
					} else {
						got := env.kube.Secret()
						if len(got) > 0 {
							return fmt.Errorf("kube secret unexpectedly not empty, got %#v", got)
						}
					}
					return nil
				})
				if err != nil {
					t.Fatalf("phase %d: %v", i, err)
				}
				err = tstest.WaitFor(2*time.Second, func() error {
					for path, want := range p.WantFiles {
						gotBs, err := os.ReadFile(filepath.Join(env.d, path))
						if err != nil {
							return fmt.Errorf("reading wanted file %q: %v", path, err)
						}
						if got := strings.TrimSpace(string(gotBs)); got != want {
							return fmt.Errorf("wrong file contents for %q, got %q want %q", path, got, want)
						}
					}
					return nil
				})
				if err != nil {
					t.Fatalf("phase %d: %v", i, err)
				}

				for url, want := range p.EndpointStatuses {
					err := tstest.WaitFor(2*time.Second, func() error {
						resp, err := http.Get(url)
						if err != nil && want != -1 {
							return fmt.Errorf("GET %s: %v", url, err)
						}
						if want > 0 && resp.StatusCode != want {
							defer resp.Body.Close()
							body, _ := io.ReadAll(resp.Body)
							return fmt.Errorf("GET %s, want %d, got %d\n%s", url, want, resp.StatusCode, string(body))
						}

						return nil
					})
					if err != nil {
						t.Fatalf("phase %d: %v", i, err)
					}
				}
			}
			waitLogLine(t, 2*time.Second, cbOut, "Startup complete, waiting for shutdown signal")
			if cmd.ProcessState != nil {
				t.Fatalf("containerboot should be running but exited with exit code %d", cmd.ProcessState.ExitCode())
			}
		})
	}
}

type lockingBuffer struct {
	sync.Mutex
	b bytes.Buffer
}

func (b *lockingBuffer) Write(bs []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.b.Write(bs)
}

func (b *lockingBuffer) String() string {
	b.Lock()
	defer b.Unlock()
	return b.b.String()
}

// waitLogLine looks for want in the contents of b.
//
// Only lines starting with 'boot: ' (the output of containerboot
// itself) are considered, and the logged timestamp is ignored.
//
// waitLogLine fails the entire test if path doesn't contain want
// before the timeout.
func waitLogLine(t *testing.T, timeout time.Duration, b *lockingBuffer, want string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(b.String(), "\n") {
			if !strings.HasPrefix(line, "boot: ") {
				continue
			}
			if strings.HasSuffix(line, " "+want) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for wanted output line %q. Output:\n%s", want, b.String())
}

// waitArgs waits until the contents of path matches wantArgs, a set
// of command lines recorded by test_tailscale.sh and
// test_tailscaled.sh.
//
// All occurrences of removeStr are removed from the file prior to
// comparison. This is used to remove the varying temporary root
// directory name from recorded commandlines, so that wantArgs can be
// a constant value.
//
// waitArgs fails the entire test if path doesn't contain wantArgs
// before the timeout.
func waitArgs(t *testing.T, timeout time.Duration, removeStr, path, wantArgs string) {
	t.Helper()
	wantArgs = strings.TrimSpace(wantArgs)
	deadline := time.Now().Add(timeout)
	var got string
	for time.Now().Before(deadline) {
		bs, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			// Don't bother logging that the file doesn't exist, it
			// should start existing soon.
			goto loop
		} else if err != nil {
			t.Logf("reading %q: %v", path, err)
			goto loop
		}
		got = strings.TrimSpace(string(bs))
		got = strings.ReplaceAll(got, removeStr, "")
		if got == wantArgs {
			return
		}
	loop:
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("waiting for args file %q to have expected output, got:\n%s\n\nWant: %s", path, got, wantArgs)
}

//go:embed test_tailscaled.sh
var fakeTailscaled []byte

//go:embed test_tailscale.sh
var fakeTailscale []byte

// localAPI is a minimal fake tailscaled LocalAPI server that presents
// just enough functionality for containerboot to function
// correctly. In practice this means it only supports querying
// tailscaled status, and panics on all other uses to make it very
// obvious that something unexpected happened.
type localAPI struct {
	FSRoot string
	Path   string // populated by Start

	srv *http.Server

	sync.Mutex
	cond   *sync.Cond
	notify *ipn.Notify
}

func (lc *localAPI) Start() error {
	path := filepath.Join(lc.FSRoot, "tmp/tailscaled.sock.fake")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}

	lc.srv = &http.Server{
		Handler: lc,
	}
	lc.Path = path
	lc.cond = sync.NewCond(&lc.Mutex)
	go lc.srv.Serve(ln)
	return nil
}

func (lc *localAPI) Close() {
	lc.srv.Close()
}

func (lc *localAPI) Notify(n *ipn.Notify) {
	if n == nil {
		return
	}
	lc.Lock()
	defer lc.Unlock()
	lc.notify = n
	lc.cond.Broadcast()
}

func (lc *localAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/localapi/v0/serve-config":
		if r.Method != "POST" {
			panic(fmt.Sprintf("unsupported method %q", r.Method))
		}
		return
	case "/localapi/v0/watch-ipn-bus":
		if r.Method != "GET" {
			panic(fmt.Sprintf("unsupported method %q", r.Method))
		}
	case "/localapi/v0/usermetrics":
		if r.Method != "GET" {
			panic(fmt.Sprintf("unsupported method %q", r.Method))
		}
		w.Write([]byte("fake metrics"))
		return
	default:
		panic(fmt.Sprintf("unsupported path %q", r.URL.Path))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	enc := json.NewEncoder(w)
	lc.Lock()
	defer lc.Unlock()
	for {
		if lc.notify != nil {
			if err := enc.Encode(lc.notify); err != nil {
				// Usually broken pipe as the test client disconnects.
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		lc.cond.Wait()
	}
}

// kubeServer is a minimal fake Kubernetes server that presents just
// enough functionality for containerboot to function correctly. In
// practice this means it only supports reading and modifying a single
// kube secret, and panics on all other uses to make it very obvious
// that something unexpected happened.
type kubeServer struct {
	FSRoot     string
	Host, Port string // populated by Start

	srv *httptest.Server

	sync.Mutex
	secret   map[string]string
	canPatch bool
}

func (k *kubeServer) Secret() map[string]string {
	k.Lock()
	defer k.Unlock()
	ret := map[string]string{}
	for k, v := range k.secret {
		ret[k] = v
	}
	return ret
}

func (k *kubeServer) SetSecret(key, val string) {
	k.Lock()
	defer k.Unlock()
	k.secret[key] = val
}

func (k *kubeServer) SetPatching(canPatch bool) {
	k.Lock()
	defer k.Unlock()
	k.canPatch = canPatch
}

func (k *kubeServer) Start(t *testing.T) {
	k.secret = map[string]string{}
	root := filepath.Join(k.FSRoot, "var/run/secrets/kubernetes.io/serviceaccount")

	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "namespace"), []byte("default"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "token"), []byte("bearer_token"), 0600); err != nil {
		t.Fatal(err)
	}

	k.srv = httptest.NewTLSServer(k)
	k.Host = k.srv.Listener.Addr().(*net.TCPAddr).IP.String()
	k.Port = strconv.Itoa(k.srv.Listener.Addr().(*net.TCPAddr).Port)

	var cert bytes.Buffer
	if err := pem.Encode(&cert, &pem.Block{Type: "CERTIFICATE", Bytes: k.srv.Certificate().Raw}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ca.crt"), cert.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func (k *kubeServer) Close() {
	k.srv.Close()
}

func (k *kubeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer bearer_token" {
		panic("client didn't provide bearer token in request")
	}
	switch r.URL.Path {
	case "/api/v1/namespaces/default/secrets/tailscale":
		k.serveSecret(w, r)
	case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
		k.serveSSAR(w, r)
	default:
		panic(fmt.Sprintf("unhandled fake kube api path %q", r.URL.Path))
	}
}

func (k *kubeServer) serveSSAR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Spec struct {
			ResourceAttributes struct {
				Verb string `json:"verb"`
			} `json:"resourceAttributes"`
		} `json:"spec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		panic(fmt.Sprintf("decoding SSAR request: %v", err))
	}
	ok := true
	if req.Spec.ResourceAttributes.Verb == "patch" {
		k.Lock()
		defer k.Unlock()
		ok = k.canPatch
	}
	// Just say yes to all SARs, we don't enforce RBAC.
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":{"allowed":%v}}`, ok)
}

func (k *kubeServer) serveSecret(w http.ResponseWriter, r *http.Request) {
	bs, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("reading request body: %v", err), http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	switch r.Method {
	case "GET":
		w.Header().Set("Content-Type", "application/json")
		ret := map[string]map[string]string{
			"data": {},
		}
		k.Lock()
		defer k.Unlock()
		for k, v := range k.secret {
			v := base64.StdEncoding.EncodeToString([]byte(v))
			ret["data"][k] = v
		}
		if err := json.NewEncoder(w).Encode(ret); err != nil {
			panic("encode failed")
		}
	case "PATCH":
		k.Lock()
		defer k.Unlock()
		if !k.canPatch {
			panic("containerboot tried to patch despite not being allowed")
		}
		switch r.Header.Get("Content-Type") {
		case "application/json-patch+json":
			req := []kubeclient.JSONPatch{}
			if err := json.Unmarshal(bs, &req); err != nil {
				panic(fmt.Sprintf("json decode failed: %v. Body:\n\n%s", err, string(bs)))
			}
			for _, op := range req {
				switch op.Op {
				case "remove":
					if !strings.HasPrefix(op.Path, "/data/") {
						panic(fmt.Sprintf("unsupported json-patch path %q", op.Path))
					}
					delete(k.secret, strings.TrimPrefix(op.Path, "/data/"))
				case "add", "replace":
					path, ok := strings.CutPrefix(op.Path, "/data/")
					if !ok {
						panic(fmt.Sprintf("unsupported json-patch path %q", op.Path))
					}
					val, ok := op.Value.(string)
					if !ok {
						panic(fmt.Sprintf("unsupported json patch value %v: cannot be converted to string", op.Value))
					}
					v, err := base64.StdEncoding.DecodeString(val)
					if err != nil {
						panic(fmt.Sprintf("json patch value %q is not base64 encoded: %v", val, err))
					}
					k.secret[path] = string(v)
				default:
					panic(fmt.Sprintf("unsupported json-patch op %q", op.Op))
				}
			}
		case "application/strategic-merge-patch+json":
			req := struct {
				Data map[string][]byte `json:"data"`
			}{}
			if err := json.Unmarshal(bs, &req); err != nil {
				panic(fmt.Sprintf("json decode failed: %v. Body:\n\n%s", err, string(bs)))
			}
			for key, val := range req.Data {
				k.secret[key] = string(val)
			}
		default:
			panic(fmt.Sprintf("unknown content type %q", r.Header.Get("Content-Type")))
		}
	default:
		panic(fmt.Sprintf("unhandled HTTP request %s %s", r.Method, r.URL))
	}
}

func mustBase64(t *testing.T, v any) string {
	b := mustJSON(t, v)
	s := base64.StdEncoding.WithPadding('=').EncodeToString(b)
	return s
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("error converting %v to json: %v", v, err)
	}
	return b
}

// egress services status given one named tailnet target specified by FQDN. As written by the proxy to its state Secret.
func egressSvcStatus(name, fqdn string) egressservices.Status {
	return egressservices.Status{
		Services: map[string]*egressservices.ServiceStatus{
			name: {
				TailnetTarget: egressservices.TailnetTarget{
					FQDN: fqdn,
				},
			},
		},
	}
}

// egress config given one named tailnet target specified by FQDN.
func egressSvcConfig(name, fqdn string) egressservices.Configs {
	return egressservices.Configs{
		name: egressservices.Config{
			TailnetTarget: egressservices.TailnetTarget{
				FQDN: fqdn,
			},
		},
	}
}

// testEnv represents the environment needed for a single sub-test so that tests
// can run in parallel.
type testEnv struct {
	kube            *kubeServer // Fake kube server.
	lapi            *localAPI   // Local TS API server.
	d               string      // Temp dir for the specific test.
	argFile         string      // File with commands test_tailscale{,d}.sh were invoked with.
	runningSockPath string      // Path to the running tailscaled socket.
	localAddrPort   int         // Port for the containerboot HTTP server.
	healthAddrPort  int         // Port for the (deprecated) containerboot health server.
}

func newTestEnv(t *testing.T) testEnv {
	d := t.TempDir()

	lapi := localAPI{FSRoot: d}
	if err := lapi.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lapi.Close)

	kube := kubeServer{FSRoot: d}
	kube.Start(t)
	t.Cleanup(kube.Close)

	tailscaledConf := &ipn.ConfigVAlpha{AuthKey: ptr.To("foo"), Version: "alpha0"}
	serveConf := ipn.ServeConfig{TCP: map[uint16]*ipn.TCPPortHandler{80: {HTTP: true}}}
	egressCfg := egressSvcConfig("foo", "foo.tailnetxyz.ts.net")

	dirs := []string{
		"var/lib",
		"usr/bin",
		"tmp",
		"dev/net",
		"proc/sys/net/ipv4",
		"proc/sys/net/ipv6/conf/all",
		"etc/tailscaled",
	}
	for _, path := range dirs {
		if err := os.MkdirAll(filepath.Join(d, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string][]byte{
		"usr/bin/tailscaled":                    fakeTailscaled,
		"usr/bin/tailscale":                     fakeTailscale,
		"usr/bin/iptables":                      fakeTailscale,
		"usr/bin/ip6tables":                     fakeTailscale,
		"dev/net/tun":                           []byte(""),
		"proc/sys/net/ipv4/ip_forward":          []byte("0"),
		"proc/sys/net/ipv6/conf/all/forwarding": []byte("0"),
		"etc/tailscaled/cap-95.hujson":          mustJSON(t, tailscaledConf),
		"etc/tailscaled/serve-config.json":      mustJSON(t, serveConf),
		filepath.Join("etc/tailscaled/", egressservices.KeyEgressServices): mustJSON(t, egressCfg),
		filepath.Join("etc/tailscaled/", egressservices.KeyHEPPings):       []byte("4"),
	}
	for path, content := range files {
		// Making everything executable is a little weird, but the
		// stuff that doesn't need to be executable doesn't care if we
		// do make it executable.
		if err := os.WriteFile(filepath.Join(d, path), content, 0700); err != nil {
			t.Fatal(err)
		}
	}

	argFile := filepath.Join(d, "args")
	runningSockPath := filepath.Join(d, "tmp/tailscaled.sock")
	var localAddrPort, healthAddrPort int
	for _, p := range []*int{&localAddrPort, &healthAddrPort} {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatalf("Failed to open listener: %v", err)
		}
		if err := ln.Close(); err != nil {
			t.Fatalf("Failed to close listener: %v", err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		*p = port
	}

	return testEnv{
		kube:            &kube,
		lapi:            &lapi,
		d:               d,
		argFile:         argFile,
		runningSockPath: runningSockPath,
		localAddrPort:   localAddrPort,
		healthAddrPort:  healthAddrPort,
	}
}
