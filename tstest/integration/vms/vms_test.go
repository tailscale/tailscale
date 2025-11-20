// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !plan9

package vms

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/pkg/sftp"
	expect "github.com/tailscale/goexpect"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/semaphore"
	"tailscale.com/tstest"
	"tailscale.com/types/logger"
)

const (
	securePassword = "hunter2"
	bucketName     = "tailscale-integration-vm-images"
)

var (
	runVMTests        = flag.Bool("run-vm-tests", false, "if set, run expensive VM based integration tests")
	noS3              = flag.Bool("no-s3", false, "if set, always download images from the public internet (risks breaking)")
	vmRamLimit        = flag.Int("ram-limit", 4096, "the maximum number of megabytes of ram that can be used for VMs, must be greater than or equal to 1024")
	useVNC            = flag.Bool("use-vnc", false, "if set, display guest vms over VNC")
	verboseLogcatcher = flag.Bool("verbose-logcatcher", true, "if set, print logcatcher to t.Logf")
	verboseQemu       = flag.Bool("verbose-qemu", true, "if set, print qemu console to t.Logf")
)

func TestDownloadImages(t *testing.T) {
	if !*runVMTests {
		t.Skip("not running integration tests (need --run-vm-tests)")
	}

	for _, d := range Distros {
		distro := d
		t.Run(distro.Name, func(t *testing.T) {
			t.Parallel()
			if strings.HasPrefix(distro.Name, "nixos") {
				t.Skip("NixOS is built on the fly, no need to download it")
			}

			fetchDistro(t, distro)
		})
	}
}

// run runs a command or fails the test.
func run(t *testing.T, dir, prog string, args ...string) {
	t.Helper()
	t.Logf("running: %s %s", prog, strings.Join(args, " "))
	tstest.FixLogs(t)

	cmd := exec.Command(prog, args...)
	cmd.Stdout = logger.FuncWriter(t.Logf)
	cmd.Stderr = logger.FuncWriter(t.Logf)
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}

// mkLayeredQcow makes a layered qcow image that allows us to keep the upstream
// VM images pristine and only do our changes on an overlay.
func mkLayeredQcow(t *testing.T, tdir string, d Distro, qcowBase string) {
	t.Helper()

	run(t, tdir, "qemu-img", "create",
		"-f", "qcow2",
		"-b", qcowBase,
		"-F", "qcow2",
		filepath.Join(tdir, d.Name+".qcow2"),
	)
}

var (
	metaDataTempl = template.Must(template.New("meta-data.yaml").Parse(metaDataTemplate))
	userDataTempl = template.Must(template.New("user-data.yaml").Parse(userDataTemplate))
)

// mkSeed makes the cloud-init seed ISO that is used to configure a VM with
// tailscale.
func mkSeed(t *testing.T, d Distro, sshKey, hostURL, tdir string, port int) {
	t.Helper()

	dir := filepath.Join(tdir, d.Name, "seed")
	os.MkdirAll(dir, 0700)

	// make meta-data
	{
		fout, err := os.Create(filepath.Join(dir, "meta-data"))
		if err != nil {
			t.Fatal(err)
		}

		err = metaDataTempl.Execute(fout, struct {
			ID       string
			Hostname string
		}{
			ID:       "31337",
			Hostname: d.Name,
		})
		if err != nil {
			t.Fatal(err)
		}

		err = fout.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	// make user-data
	{
		fout, err := os.Create(filepath.Join(dir, "user-data"))
		if err != nil {
			t.Fatal(err)
		}

		err = userDataTempl.Execute(fout, struct {
			SSHKey     string
			HostURL    string
			Hostname   string
			Port       int
			InstallPre string
			Password   string
		}{
			SSHKey:     strings.TrimSpace(sshKey),
			HostURL:    hostURL,
			Hostname:   d.Name,
			Port:       port,
			InstallPre: d.InstallPre(),
			Password:   securePassword,
		})
		if err != nil {
			t.Fatal(err)
		}

		err = fout.Close()
		if err != nil {
			t.Fatal(err)
		}
	}

	args := []string{
		"-output", filepath.Join(dir, "seed.iso"),
		"-volid", "cidata", "-joliet", "-rock",
		filepath.Join(dir, "meta-data"),
		filepath.Join(dir, "user-data"),
	}

	run(t, tdir, "genisoimage", args...)
}

// ipMapping maps a hostname, SSH port and SSH IP together
type ipMapping struct {
	name string
	port int
	ip   string
}

// getProbablyFreePortNumber does what it says on the tin, but as a side effect
// it is a kind of racy function. Do not use this carelessly.
//
// This is racy because it does not "lock" the port number with the OS. The
// "random" port number that is returned here is most likely free to use, however
// it is difficult to be 100% sure. This function should be used with care. It
// will probably do what you want, but it is very easy to hold this wrong.
func getProbablyFreePortNumber() (int, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}

	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return 0, err
	}

	portNum, err := strconv.Atoi(port)
	if err != nil {
		return 0, err
	}

	return portNum, nil
}

func setupTests(t *testing.T) {
	ramsem.once.Do(func() {
		ramsem.sem = semaphore.NewWeighted(int64(*vmRamLimit))
	})

	if !*runVMTests {
		t.Skip("not running integration tests (need --run-vm-tests)")
	}

	os.Setenv("CGO_ENABLED", "0")

	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		t.Logf("hint: nix-shell -p go -p qemu -p cdrkit --run 'go test --v --timeout=60m --run-vm-tests'")
		t.Fatalf("missing dependency: %v", err)
	}

	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Logf("hint: nix-shell -p go -p qemu -p cdrkit --run 'go test --v --timeout=60m --run-vm-tests'")
		t.Fatalf("missing dependency: %v", err)
	}
}

var ramsem struct {
	once sync.Once
	sem  *semaphore.Weighted
}

func testOneDistribution(t *testing.T, n int, distro Distro) {
	setupTests(t)

	ctx, done := context.WithCancel(context.Background())
	t.Cleanup(done)

	h := newHarness(t)
	dir := t.TempDir()

	err := ramsem.sem.Acquire(ctx, int64(distro.MemoryMegs))
	if err != nil {
		t.Fatalf("can't acquire ram semaphore: %v", err)
	}
	t.Cleanup(func() { ramsem.sem.Release(int64(distro.MemoryMegs)) })

	vm := h.mkVM(t, n, distro, h.pubKey, h.loginServerURL, dir)
	vm.waitStartup(t)

	h.testDistro(t, distro, h.waitForIPMap(t, vm, distro))
}

func (h *Harness) waitForIPMap(t *testing.T, vm *vmInstance, distro Distro) ipMapping {
	t.Helper()
	var ipm ipMapping

	waiter := time.NewTicker(time.Second)
	defer waiter.Stop()
	for {
		var ok bool

		h.ipMu.Lock()
		ipm, ok = h.ipMap[distro.Name]
		h.ipMu.Unlock()

		if ok {
			break
		}
		if !vm.running() {
			t.Fatal("vm not running")
		}
		<-waiter.C
	}
	return ipm
}

func (h *Harness) setupSSHShell(t *testing.T, d Distro, ipm ipMapping) (*ssh.ClientConfig, *ssh.Client) {
	signer := h.signer

	t.Helper()
	port := ipm.port
	hostport := fmt.Sprintf("127.0.0.1:%d", port)
	ccfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer), ssh.Password(securePassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// NOTE(Xe): This deadline loop helps to make things a bit faster, centos
	// sometimes is slow at starting its sshd and will sometimes randomly kill
	// SSH sessions on transition to multi-user.target. I don't know why they
	// don't use socket activation.
	const maxRetries = 5
	var working bool
	for range maxRetries {
		cli, err := ssh.Dial("tcp", hostport, ccfg)
		if err == nil {
			working = true
			cli.Close()
			break
		}

		time.Sleep(10 * time.Second)
	}

	if !working {
		t.Fatalf("can't connect to %s, tried %d times", hostport, maxRetries)
	}

	t.Logf("about to ssh into 127.0.0.1:%d", port)
	cli, err := ssh.Dial("tcp", hostport, ccfg)
	if err != nil {
		t.Fatal(err)
	}
	h.copyBinaries(t, d, cli)

	return ccfg, cli
}

func (h *Harness) testDistro(t *testing.T, d Distro, ipm ipMapping) {
	loginServer := h.loginServerURL
	ccfg, cli := h.setupSSHShell(t, d, ipm)

	timeout := 30 * time.Second

	t.Run("start-tailscale", func(t *testing.T) {
		var batch = []expect.Batcher{
			&expect.BExp{R: `(\#)`},
		}

		switch d.InitSystem {
		case "openrc":
			// NOTE(Xe): this is a sin, however openrc doesn't really have the concept
			// of service readiness. If this sleep is removed then tailscale will not be
			// ready once the `tailscale up` command is sent. This is not ideal, but I
			// am not really sure there is a good way around this without a delay of
			// some kind.
			batch = append(batch, &expect.BSnd{S: "rc-service tailscaled start && sleep 2\n"})
		case "systemd":
			batch = append(batch, &expect.BSnd{S: "systemctl start tailscaled.service\n"})
		}

		batch = append(batch, &expect.BExp{R: `(\#)`})

		runTestCommands(t, timeout, cli, batch)
	})

	t.Run("login", func(t *testing.T) {
		runTestCommands(t, timeout, cli, []expect.Batcher{
			&expect.BSnd{S: fmt.Sprintf("tailscale up --login-server=%s\n", loginServer)},
			&expect.BSnd{S: "echo Success.\n"},
			&expect.BExp{R: `Success.`},
		})
	})

	t.Run("tailscale status", func(t *testing.T) {
		dur := 100 * time.Millisecond
		var outp []byte
		var err error

		// NOTE(Xe): retry `tailscale status` a few times until it works. When tailscaled
		// starts with testcontrol sometimes there can be up to a few seconds where
		// tailscaled is in an unknown state on these virtual machines. This exponential
		// delay loop should delay long enough for tailscaled to be ready.
		for count := 0; count < 10; count++ {
			sess := getSession(t, cli)

			outp, err = sess.CombinedOutput("tailscale status")
			if err == nil {
				t.Logf("tailscale status: %s", outp)
				if !strings.Contains(string(outp), "100.64.0.1") {
					t.Fatal("can't find tester IP")
				}
				return
			}
			time.Sleep(dur)
			dur = dur * 2
		}

		t.Log(string(outp))
		t.Fatalf("error: %v", err)
	})

	t.Run("dump routes", func(t *testing.T) {
		sess, err := cli.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		sess.Stdout = logger.FuncWriter(t.Logf)
		sess.Stderr = logger.FuncWriter(t.Logf)
		err = sess.Run("ip route show table 52")
		if err != nil {
			t.Fatal(err)
		}

		sess, err = cli.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		sess.Stdout = logger.FuncWriter(t.Logf)
		sess.Stderr = logger.FuncWriter(t.Logf)
		err = sess.Run("ip -6 route show table 52")
		if err != nil {
			t.Fatal(err)
		}
	})

	for _, tt := range []struct {
		ipProto string
		addr    netip.Addr
	}{
		{"ipv4", h.testerV4},
	} {
		t.Run(tt.ipProto+"-address", func(t *testing.T) {
			sess := getSession(t, cli)

			ipBytes, err := sess.Output("tailscale ip -" + string(tt.ipProto[len(tt.ipProto)-1]))
			if err != nil {
				t.Fatalf("can't get IP: %v", err)
			}

			netip.MustParseAddr(string(bytes.TrimSpace(ipBytes)))
		})

		t.Run("ping-"+tt.ipProto, func(t *testing.T) {
			h.testPing(t, tt.addr, cli)
		})

		t.Run("outgoing-tcp-"+tt.ipProto, func(t *testing.T) {
			h.testOutgoingTCP(t, tt.addr, cli)
		})
	}

	t.Run("incoming-ssh-ipv4", func(t *testing.T) {
		sess, err := cli.NewSession()
		if err != nil {
			t.Fatalf("can't make incoming session: %v", err)
		}
		defer sess.Close()
		ipBytes, err := sess.Output("tailscale ip -4")
		if err != nil {
			t.Fatalf("can't run `tailscale ip -4`: %v", err)
		}
		ip := string(bytes.TrimSpace(ipBytes))

		conn, err := h.testerDialer.Dial("tcp", net.JoinHostPort(ip, "22"))
		if err != nil {
			t.Fatalf("can't dial connection to vm: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		sshConn, chanchan, reqchan, err := ssh.NewClientConn(conn, net.JoinHostPort(ip, "22"), ccfg)
		if err != nil {
			t.Fatalf("can't negotiate connection over tailscale: %v", err)
		}
		defer sshConn.Close()

		cli := ssh.NewClient(sshConn, chanchan, reqchan)
		defer cli.Close()

		sess, err = cli.NewSession()
		if err != nil {
			t.Fatalf("can't make SSH session with VM: %v", err)
		}
		defer sess.Close()

		testIPBytes, err := sess.Output("tailscale ip -4")
		if err != nil {
			t.Fatalf("can't run command on remote VM: %v", err)
		}

		if !bytes.Equal(testIPBytes, ipBytes) {
			t.Fatalf("wanted reported ip to be %q, got: %q", string(ipBytes), string(testIPBytes))
		}
	})

	t.Run("outgoing-udp-ipv4", func(t *testing.T) {
		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("can't get working directory: %v", err)
		}
		dir := t.TempDir()
		run(t, cwd, "go", "build", "-o", filepath.Join(dir, "udp_tester"), "./udp_tester.go")

		sftpCli, err := sftp.NewClient(cli)
		if err != nil {
			t.Fatalf("can't connect over sftp to copy binaries: %v", err)
		}
		defer sftpCli.Close()

		copyFile(t, sftpCli, filepath.Join(dir, "udp_tester"), "/udp_tester")

		uaddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("::", "0"))
		if err != nil {
			t.Fatalf("can't resolve udp listener addr: %v", err)
		}

		buf := make([]byte, 2048)

		ln, err := net.ListenUDP("udp", uaddr)
		if err != nil {
			t.Fatalf("can't listen for UDP traffic: %v", err)
		}
		defer ln.Close()

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)

		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				sess, err := cli.NewSession()
				if err != nil {
					t.Errorf("can't open session: %v", err)
					return
				}
				defer sess.Close()

				sess.Stdin = strings.NewReader("hi")
				sess.Stdout = logger.FuncWriter(t.Logf)
				sess.Stderr = logger.FuncWriter(t.Logf)

				_, port, _ := net.SplitHostPort(ln.LocalAddr().String())

				cmd := fmt.Sprintf("/udp_tester -client %s\n", net.JoinHostPort("100.64.0.1", port))
				t.Logf("sending packet: %s", cmd)
				err = sess.Run(cmd)
				if err != nil {
					t.Logf("can't send UDP packet: %v", err)
				}

				time.Sleep(10 * time.Millisecond)
			}
		}()

		t.Log("listening for packet")
		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}

		if n == 0 {
			t.Fatal("got nothing")
		}

		if !bytes.Contains(buf, []byte("hi")) {
			t.Fatal("did not get UDP message")
		}
	})

	t.Run("incoming-udp-ipv4", func(t *testing.T) {
		// vms_test.go:947: can't dial: socks connect udp 127.0.0.1:36497->100.64.0.2:33409: network not implemented
		t.Skip("can't make outgoing sockets over UDP with our socks server")

		sess, err := cli.NewSession()
		if err != nil {
			t.Fatalf("can't open session: %v", err)
		}
		defer sess.Close()

		ip, err := sess.Output("tailscale ip -4")
		if err != nil {
			t.Fatalf("can't nab ipv4 address: %v", err)
		}

		port, err := getProbablyFreePortNumber()
		if err != nil {
			t.Fatalf("unable to fetch port number: %v", err)
		}

		go func() {
			time.Sleep(10 * time.Millisecond)

			conn, err := h.testerDialer.Dial("udp", net.JoinHostPort(string(bytes.TrimSpace(ip)), strconv.Itoa(port)))
			if err != nil {
				t.Errorf("can't dial: %v", err)
			}

			fmt.Fprint(conn, securePassword)
		}()

		sess, err = cli.NewSession()
		if err != nil {
			t.Fatalf("can't open session: %v", err)
		}
		defer sess.Close()
		sess.Stderr = logger.FuncWriter(t.Logf)

		msg, err := sess.Output(
			fmt.Sprintf(
				"/udp_tester -server %s",
				net.JoinHostPort(string(bytes.TrimSpace(ip)), strconv.Itoa(port)),
			),
		)

		if msg := string(bytes.TrimSpace(msg)); msg != securePassword {
			t.Fatalf("wanted %q from vm, got: %q", securePassword, msg)
		}
	})

	t.Run("dns-test", func(t *testing.T) {
		t.Run("etc-resolv-conf", func(t *testing.T) {
			sess := getSession(t, cli)
			sess.Stdout = logger.FuncWriter(t.Logf)
			sess.Stderr = logger.FuncWriter(t.Errorf)
			if err := sess.Run("cat /etc/resolv.conf"); err != nil {
				t.Fatal(err)
			}
		})

		cwd, err := os.Getwd()
		if err != nil {
			t.Fatalf("can't get working directory: %v", err)
		}
		dir := t.TempDir()
		run(t, cwd, "go", "build", "-o", filepath.Join(dir, "dns_tester"), "./dns_tester.go")

		sftpCli, err := sftp.NewClient(cli)
		if err != nil {
			t.Fatalf("can't connect over sftp to copy binaries: %v", err)
		}
		defer sftpCli.Close()

		copyFile(t, sftpCli, filepath.Join(dir, "dns_tester"), "/dns_tester")

		for _, record := range []string{"extratest.record", "extratest"} {
			t.Run(record, func(t *testing.T) {
				sess := getSession(t, cli)
				sess.Stderr = logger.FuncWriter(t.Errorf)
				msg, err := sess.Output("/dns_tester " + record)
				if err != nil {
					t.Fatal(err)
				}

				msg = bytes.TrimSpace(msg)
				if want := []byte("1.2.3.4"); !bytes.Contains(msg, want) {
					t.Fatalf("got: %q, want: %q", msg, want)
				}
			})
		}
	})
}

func runTestCommands(t *testing.T, timeout time.Duration, cli *ssh.Client, batch []expect.Batcher) {
	e, _, err := expect.SpawnSSH(cli, timeout,
		expect.Verbose(true),
		expect.VerboseWriter(logger.FuncWriter(t.Logf)),

		// // NOTE(Xe): if you get a timeout, uncomment this region to have the raw
		// // output be sent to the test log quicker.
		// expect.Tee(nopWriteCloser{logger.FuncWriter(t.Logf)}),
	)
	if err != nil {
		t.Fatalf("%s: can't register a shell session: %v", cli.RemoteAddr(), err)
	}
	defer e.Close()

	_, err = e.ExpectBatch(batch, timeout)
	if err != nil {
		sess, terr := cli.NewSession()
		if terr != nil {
			t.Fatalf("can't dump tailscaled logs on failed test: %v", terr)
		}
		sess.Stdout = logger.FuncWriter(t.Logf)
		sess.Stderr = logger.FuncWriter(t.Logf)
		terr = sess.Run("journalctl -u tailscaled")
		if terr != nil {
			t.Fatalf("can't dump tailscaled logs on failed test: %v", terr)
		}
		t.Fatalf("not successful: %v", err)
	}
}
