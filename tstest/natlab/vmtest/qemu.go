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
	"strconv"
	"strings"
	"time"

	"tailscale.com/tstest/natlab/vnet"
)

// startQEMU launches a QEMU process for the given node.
func (e *Env) startQEMU(n *Node) error {
	if n.os.IsGokrazy {
		return e.startGokrazyQEMU(n)
	}
	return e.startCloudQEMU(n)
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
	qmpSock := filepath.Join(e.tempDir, n.name+"-qmp.sock")

	args := []string{
		"-machine", "q35,accel=kvm",
		"-m", fmt.Sprintf("%dM", n.os.MemoryMB),
		"-cpu", "host",
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

// launchQEMU starts a qemu-system-x86_64 process with the given args.
// VM console output goes to logPath (via QEMU's -serial or -chardev).
// QEMU's own stdout/stderr go to logPath.qemu for diagnostics.
func (e *Env) launchQEMU(name, logPath string, args []string) error {
	cmd := exec.Command("qemu-system-x86_64", args...)
	// Send stdout/stderr to the log file for any QEMU diagnostic messages.
	// Stdin must be /dev/null to prevent QEMU from trying to read.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return fmt.Errorf("open /dev/null: %w", err)
	}
	cmd.Stdin = devNull
	qemuLog, err := os.Create(logPath + ".qemu")
	if err != nil {
		devNull.Close()
		return err
	}
	cmd.Stdout = qemuLog
	cmd.Stderr = qemuLog
	if err := cmd.Start(); err != nil {
		devNull.Close()
		qemuLog.Close()
		return fmt.Errorf("qemu for %s: %w", name, err)
	}
	e.t.Logf("launched QEMU for %s (pid %d), log: %s", name, cmd.Process.Pid, logPath)
	e.qemuProcs = append(e.qemuProcs, cmd)

	// Start tailing the VM console log for the web UI.
	if e.ctx != nil {
		go e.tailLogFile(e.ctx, name, logPath)
	}
	e.t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		devNull.Close()
		qemuLog.Close()
		// Dump tail of VM log on failure for debugging.
		if e.t.Failed() {
			if data, err := os.ReadFile(logPath); err == nil {
				lines := bytes.Split(data, []byte("\n"))
				start := 0
				if len(lines) > 50 {
					start = len(lines) - 50
				}
				e.t.Logf("=== last 50 lines of %s log ===", name)
				for _, line := range lines[start:] {
					e.t.Logf("[%s] %s", name, line)
				}
			}
		}
	})
	return nil
}

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
	conn.SetDeadline(time.Now().Add(5 * time.Second))

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

	// Query "info usernet" via human-monitor-command.
	fmt.Fprintf(conn, `{"execute":"human-monitor-command","arguments":{"command-line":"info usernet"}}`+"\n")
	var hmpResp struct {
		Return string `json:"return"`
	}
	if err := dec.Decode(&hmpResp); err != nil {
		return 0, fmt.Errorf("reading info usernet response: %w", err)
	}

	// Parse the port from output like:
	//   TCP[HOST_FORWARD]  12       127.0.0.1 35323       10.0.2.15    22
	re := regexp.MustCompile(`TCP\[HOST_FORWARD\]\s+\d+\s+127\.0\.0\.1\s+(\d+)\s+`)
	m := re.FindStringSubmatch(hmpResp.Return)
	if m == nil {
		return 0, fmt.Errorf("no hostfwd port found in: %s", hmpResp.Return)
	}
	return strconv.Atoi(m[1])
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
