// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package vmtest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest/natlab/vnet"
)

// qemuAccelArgs returns QEMU command-line flags for hardware-accelerated
// virtualisation when available, or nil to fall back to TCG (software
// emulation). On Linux, KVM is used when /dev/kvm is accessible. On other
// platforms (macOS, etc.) TCG is used, which allows the tests to run
// without a same-architecture hypervisor at the cost of speed.
func qemuAccelArgs() []string {
	if runtime.GOOS == "linux" {
		if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
			f.Close()
			return []string{"-enable-kvm", "-cpu", "host"}
		}
	}
	return nil
}

// gokrazyPlatform boots gokrazy (Linux) VMs via QEMU.
type gokrazyPlatform struct{}

func (gokrazyPlatform) planSteps(e *Env, n *Node) {
	e.Step("Build gokrazy image")
	e.Step("Launch QEMU: " + n.name)
}

func (gokrazyPlatform) boot(ctx context.Context, e *Env, n *Node) error {
	e.gokrazyOnce.Do(func() {
		step := e.Step("Build gokrazy image")
		step.Begin()
		if err := e.ensureGokrazy(ctx); err != nil {
			step.End(err)
			e.t.Fatalf("ensureGokrazy: %v", err)
		}
		step.End(nil)
	})

	e.ensureQEMUSocket()

	vmStep := e.Step("Launch QEMU: " + n.name)
	vmStep.Begin()
	if err := e.startGokrazyQEMU(n); err != nil {
		vmStep.End(err)
		return err
	}
	vmStep.End(nil)
	return nil
}

// qemuCloudPlatform boots cloud images (Ubuntu, Debian, FreeBSD) via QEMU.
type qemuCloudPlatform struct{}

func (qemuCloudPlatform) planSteps(e *Env, n *Node) {
	e.Step(fmt.Sprintf("Compile %s_%s binaries", n.os.GOOS(), n.os.GOARCH()))
	e.Step(fmt.Sprintf("Prepare %s image", n.os.Name))
	e.Step("Launch QEMU: " + n.name)
}

func (qemuCloudPlatform) boot(ctx context.Context, e *Env, n *Node) error {
	goos, goarch := n.os.GOOS(), n.os.GOARCH()

	e.ensureCompiled(ctx, goos, goarch)

	if err := e.ensureImage(ctx, n.os); err != nil {
		return err
	}

	e.ensureQEMUSocket()

	vmStep := e.Step("Launch QEMU: " + n.name)
	vmStep.Begin()
	if err := e.startCloudQEMU(n); err != nil {
		vmStep.End(err)
		return err
	}
	vmStep.End(nil)
	return nil
}

// startGokrazyQEMU launches a QEMU process for a gokrazy node.
// This follows the same pattern as tstest/integration/nat/nat_test.go.
func (e *Env) startGokrazyQEMU(n *Node) error {
	disk := filepath.Join(e.tempDir, fmt.Sprintf("%s.qcow2", n.name))
	if err := createOverlay(e.gokrazyBase, disk); err != nil {
		return err
	}

	var envBuf bytes.Buffer
	for _, env := range n.vnetNode.Env() {
		fmt.Fprintf(&envBuf, " tailscaled.env=%s=%s", env.Key, env.Value)
	}
	sysLogAddr := net.JoinHostPort(vnet.FakeSyslogIPv4().String(), "995")
	if n.vnetNode.IsV6Only() {
		fmt.Fprintf(&envBuf, " tta.nameserver=%s", vnet.FakeDNSIPv6())
		sysLogAddr = net.JoinHostPort(vnet.FakeSyslogIPv6().String(), "995")
	}

	logPath := filepath.Join(e.tempDir, n.name+".log")

	args := []string{
		"-M", "microvm,isa-serial=off",
		"-m", fmt.Sprintf("%dM", n.os.MemoryMB),
		"-nodefaults", "-no-user-config", "-nographic",
		"-kernel", e.gokrazyKernel,
		"-append", "console=hvc0 root=PARTUUID=60c24cc1-f3f9-427a-8199-76baa2d60001/PARTNROFF=1 ro init=/gokrazy/init panic=10 oops=panic pci=off nousb tsc=unstable clocksource=hpet gokrazy.remote_syslog.target=" + sysLogAddr + " tailscale-tta=1" + envBuf.String(),
		"-drive", "id=blk0,file=" + disk + ",format=qcow2",
		"-device", "virtio-blk-device,drive=blk0",
		"-device", "virtio-serial-device",
		"-device", "virtio-rng-device",
		"-chardev", "file,id=virtiocon0,path=" + logPath,
		"-device", "virtconsole,chardev=virtiocon0",
	}

	// Add network devices — one per NIC.
	for i := range n.vnetNode.NumNICs() {
		mac := n.vnetNode.NICMac(i)
		netdevID := fmt.Sprintf("net%d", i)
		args = append(args,
			"-netdev", fmt.Sprintf("stream,id=%s,addr.type=unix,addr.path=%s", netdevID, e.sockAddr),
			"-device", fmt.Sprintf("virtio-net-device,netdev=%s,mac=%s", netdevID, mac),
		)
	}

	args = append(args, qemuAccelArgs()...)
	return e.launchQEMU(n.name, logPath, args)
}

// startCloudQEMU launches a QEMU process for a cloud image (Ubuntu, Debian, FreeBSD, etc).
func (e *Env) startCloudQEMU(n *Node) error {
	basePath := cachedImagePath(n.os)
	disk := filepath.Join(e.tempDir, fmt.Sprintf("%s.qcow2", n.name))
	if err := createOverlay(basePath, disk); err != nil {
		return err
	}

	// Create a seed ISO with cloud-init config (meta-data, user-data, network-config).
	// This MUST be a local ISO (not HTTP) so cloud-init reads network-config during
	// init-local, before systemd-networkd-wait-online blocks boot.
	seedISO, err := e.createCloudInitISO(n)
	if err != nil {
		return fmt.Errorf("creating cloud-init ISO: %w", err)
	}

	logPath := filepath.Join(e.tempDir, n.name+".log")
	qmpSock := filepath.Join(e.sockDir, n.name+"-qmp.sock")

	args := []string{
		"-machine", "q35",
		"-m", fmt.Sprintf("%dM", n.os.MemoryMB),
		"-smp", "2",
		"-display", "none",
		"-drive", fmt.Sprintf("file=%s,if=virtio", disk),
		"-drive", fmt.Sprintf("file=%s,if=virtio,media=cdrom,readonly=on", seedISO),
		"-smbios", "type=1,serial=ds=nocloud",
		"-serial", "file:" + logPath,
		"-qmp", "unix:" + qmpSock + ",server,nowait",
	}

	// Add network devices — one per NIC.
	// romfile="" disables the iPXE option ROM entirely, saving ~5s per NIC at boot
	// and avoiding "duplicate fw_cfg file name" errors with multiple NICs.
	for i := range n.vnetNode.NumNICs() {
		mac := n.vnetNode.NICMac(i)
		netdevID := fmt.Sprintf("net%d", i)
		args = append(args,
			"-netdev", fmt.Sprintf("stream,id=%s,addr.type=unix,addr.path=%s", netdevID, e.sockAddr),
			"-device", fmt.Sprintf("virtio-net-pci,netdev=%s,mac=%s,romfile=", netdevID, mac),
		)
	}

	// Add a debug NIC with user-mode networking for SSH access from the host.
	// Use port 0 so the OS picks a free port; we query the actual port via QMP after launch.
	args = append(args,
		"-netdev", "user,id=debug0,hostfwd=tcp:127.0.0.1:0-:22",
		"-device", "virtio-net-pci,netdev=debug0,romfile=",
	)

	args = append(args, qemuAccelArgs()...)

	if err := e.launchQEMU(n.name, logPath, args); err != nil {
		return err
	}

	// Query QMP to find the actual SSH port that QEMU allocated.
	port, err := qmpQueryHostFwd(qmpSock)
	if err != nil {
		return fmt.Errorf("querying SSH port via QMP: %w", err)
	}
	n.sshPort = port
	e.t.Logf("[%s] SSH debug: ssh -p %d root@127.0.0.1 (password: root)", n.name, port)
	return nil
}

// qemuRun is one running qemu-system-x86_64 process plus the file handles
// the wrapping code holds open on its behalf. kill tears the whole thing
// down (used both for normal cleanup and for the in-flight retry path).
type qemuRun struct {
	cmd        *exec.Cmd
	parentPipe *os.File
	devNull    *os.File
	qemuLog    *os.File
}

func (r *qemuRun) kill() {
	killProcessTree(r.cmd)
	r.cmd.Wait()
	r.parentPipe.Close()
	r.devNull.Close()
	r.qemuLog.Close()
}

// launchQEMU starts a qemu-system-x86_64 process with the given args and
// watches for console activity. If the guest produces no output within
// stuckTimeout (empty console *and* QEMU has not exited with an error),
// the QEMU process is killed and re-launched. This works around CI
// hypervisor flakes seen on shared GitHub Actions runners where a QEMU
// process starts but its vCPU never makes any forward progress (the
// failure presents as both the virtconsole log and the QEMU stderr log
// being zero bytes after many minutes, with the vnet stream socket
// connected but no packet ever sent).
//
// VM console output goes to logPath (via QEMU's -serial or -chardev).
// QEMU's own stdout/stderr go to logPath.qemu for diagnostics.
func (e *Env) launchQEMU(name, logPath string, args []string) error {
	// stuckTimeout is generous: a healthy VM prints SeaBIOS/kernel
	// output within ~1-2s on KVM, but slow shared CI hardware can lag.
	// Setting it too low risks killing a healthy-but-slow VM; setting it
	// too high masks the wedge case we want to recover from.
	const stuckTimeout = 45 * time.Second
	const maxAttempts = 3

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			e.t.Logf("[%s] QEMU made no progress in %v; killing and retrying (attempt %d/%d)", name, stuckTimeout, attempt, maxAttempts)
			// QEMU's -chardev file backend opens append-mode, so stale
			// bytes from a previous attempt would falsely trip the
			// progress check on retry. Truncate it.
			os.Truncate(logPath, 0)
		}
		run, err := e.startQEMUOnce(name, logPath, args)
		if err != nil {
			lastErr = err
			continue
		}
		if waitForConsoleProgress(logPath, stuckTimeout) {
			e.qemuProcs = append(e.qemuProcs, run.cmd)
			if e.ctx != nil {
				go e.tailLogFile(e.ctx, name, logPath)
			}
			e.t.Cleanup(func() {
				run.kill()
				// Dump tail of VM log and QEMU's own stderr on failure.
				// The console log (logPath) is empty when the guest never
				// produced output (e.g. QEMU exited before the kernel ran);
				// in that case the .qemu file holds the only diagnostic —
				// KVM errors, "kvm not available", CPU model mismatch, etc.
				if e.t.Failed() {
					dumpLogTail(e.t, name, "console", logPath)
					dumpLogTail(e.t, name, "qemu stderr", logPath+".qemu")
				}
			})
			return nil
		}
		lastErr = fmt.Errorf("QEMU for %s produced no console output in %v", name, stuckTimeout)
		run.kill()
	}
	return fmt.Errorf("QEMU for %s failed after %d attempts: %w", name, maxAttempts, lastErr)
}

// startQEMUOnce starts a single qemu-system-x86_64 process. On success the
// returned qemuRun owns the process and all file handles; the caller must
// invoke kill (either inline for a retry or via t.Cleanup for the
// surviving attempt).
func (e *Env) startQEMUOnce(name, logPath string, args []string) (*qemuRun, error) {
	cmd := exec.Command("qemu-system-x86_64", args...)
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return nil, fmt.Errorf("open /dev/null: %w", err)
	}
	cmd.Stdin = devNull
	qemuLog, err := os.Create(logPath + ".qemu")
	if err != nil {
		devNull.Close()
		return nil, err
	}
	cmd.Stdout = qemuLog
	cmd.Stderr = qemuLog
	parentPipe, err := killWithParent(cmd)
	if err != nil {
		devNull.Close()
		qemuLog.Close()
		return nil, fmt.Errorf("killWithParent: %w", err)
	}
	if err := cmd.Start(); err != nil {
		parentPipe.Close()
		devNull.Close()
		qemuLog.Close()
		return nil, fmt.Errorf("qemu for %s: %w", name, err)
	}
	e.t.Logf("launched QEMU for %s (pid %d), log: %s", name, cmd.Process.Pid, logPath)
	return &qemuRun{
		cmd:        cmd,
		parentPipe: parentPipe,
		devNull:    devNull,
		qemuLog:    qemuLog,
	}, nil
}

// waitForConsoleProgress polls logPath until its size is non-zero or
// timeout elapses. It returns true on observed forward progress (any
// bytes written), false on timeout.
func waitForConsoleProgress(logPath string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(logPath); err == nil && fi.Size() > 0 {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// dumpLogTail prints the last 50 lines of the file at path to the test log,
// prefixed with the VM name and kind (e.g. "console", "qemu stderr"). It is
// a no-op (with a short note) if the file can't be read or is empty, so
// callers can use it unconditionally on test failure.
func dumpLogTail(t testing.TB, name, kind, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("=== %s %s log unavailable: %v ===", name, kind, err)
		return
	}
	if len(data) == 0 {
		t.Logf("=== %s %s log is empty ===", name, kind)
		return
	}
	lines := bytes.Split(data, []byte("\n"))
	start := 0
	if len(lines) > 50 {
		start = len(lines) - 50
	}
	t.Logf("=== last 50 lines of %s %s log ===", name, kind)
	for _, line := range lines[start:] {
		t.Logf("[%s] %s", name, line)
	}
}

// hostFwdRe matches a single TCP[HOST_FORWARD] line from QEMU's
// "info usernet" human-monitor command output, e.g.:
//
//	TCP[HOST_FORWARD]  12       127.0.0.1 35323       10.0.2.15    22
var hostFwdRe = regexp.MustCompile(`TCP\[HOST_FORWARD\]\s+\d+\s+127\.0\.0\.1\s+(\d+)\s+`)

// qmpQueryHostFwd connects to a QEMU QMP socket and queries the host port
// assigned to the first TCP host forward rule (the SSH debug port).
func qmpQueryHostFwd(sockPath string) (int, error) {
	// Wait for the QMP socket to appear.
	var conn net.Conn
	for range 50 {
		var err error
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if conn == nil {
		return 0, fmt.Errorf("QMP socket %s not available", sockPath)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	// Read the QMP greeting.
	var greeting json.RawMessage
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&greeting); err != nil {
		return 0, fmt.Errorf("reading QMP greeting: %w", err)
	}

	// Send qmp_capabilities to initialize.
	fmt.Fprintf(conn, `{"execute":"qmp_capabilities"}`+"\n")
	var capsResp json.RawMessage
	if err := dec.Decode(&capsResp); err != nil {
		return 0, fmt.Errorf("reading qmp_capabilities response: %w", err)
	}

	// Poll "info usernet" until the SLIRP host-forward rule appears.
	// On slow runners (e.g. GitHub Actions) QEMU sometimes returns an
	// empty "info usernet" if we query it before user-mode networking
	// has finished wiring up the forward, so single-shot lookups fail.
	deadline := time.Now().Add(10 * time.Second)
	var lastReturn string
	for {
		fmt.Fprintf(conn, `{"execute":"human-monitor-command","arguments":{"command-line":"info usernet"}}`+"\n")
		var hmpResp struct {
			Return string `json:"return"`
		}
		if err := dec.Decode(&hmpResp); err != nil {
			return 0, fmt.Errorf("reading info usernet response: %w", err)
		}
		lastReturn = hmpResp.Return
		if m := hostFwdRe.FindStringSubmatch(hmpResp.Return); m != nil {
			return strconv.Atoi(m[1])
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return 0, fmt.Errorf("no hostfwd port found after waiting: %q", lastReturn)
}

// tailLogFile tails a VM's serial console log file and publishes each line
// as an EventConsoleOutput to the event bus for the web UI.
func (e *Env) tailLogFile(ctx context.Context, name, logPath string) {
	// Wait for the file to appear (QEMU may not have created it yet).
	var f *os.File
	for {
		var err error
		f, err = os.Open(logPath)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	defer f.Close()

	// Read the file in a loop, tracking our position manually.
	// We can't use bufio.Scanner because it caches EOF and won't
	// pick up new data appended by QEMU after the first EOF.
	var buf []byte
	var partial string // incomplete line (no trailing newline yet)
	readBuf := make([]byte, 4096)
	for {
		n, err := f.Read(readBuf)
		if n > 0 {
			buf = append(buf, readBuf[:n]...)
			// Split into complete lines.
			for {
				idx := bytes.IndexByte(buf, '\n')
				if idx < 0 {
					break
				}
				line := partial + string(buf[:idx])
				partial = ""
				buf = buf[idx+1:]
				// Strip trailing \r from serial consoles.
				line = strings.TrimRight(line, "\r")
				if line == "" {
					continue
				}
				e.appendConsoleLine(name, line)
				e.eventBus.Publish(VMEvent{
					NodeName: name,
					Type:     EventConsoleOutput,
					Message:  line,
				})
			}
			if len(buf) > 0 {
				partial = string(buf)
				buf = buf[:0]
			}
		}
		if err != nil || n == 0 {
			// EOF or error — wait for more data.
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
}
