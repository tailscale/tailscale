// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
)

var runVMTests = flag.Bool("run-vm-tests", false, "run tests that require a VM")

func findKernelPath(t *testing.T) string {
	t.Helper()
	goModPath := filepath.Join("..", "go.mod")
	b, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	mf, err := modfile.Parse("go.mod", b, nil)
	if err != nil {
		t.Fatalf("parsing go.mod: %v", err)
	}
	goModB, err := exec.Command("go", "env", "GOMODCACHE").CombinedOutput()
	if err != nil {
		t.Fatalf("go env GOMODCACHE: %v", err)
	}
	for _, r := range mf.Require {
		if r.Mod.Path == "github.com/tailscale/gokrazy-kernel" {
			return strings.TrimSpace(string(goModB)) + "/" + r.Mod.String() + "/vmlinuz"
		}
	}
	t.Fatal("failed to find gokrazy-kernel in go.mod")
	return ""
}

// gptPartuuid returns the GPT PARTUUID for a gokrazy appliance partition,
// matching the scheme used by monogok: fnv32a(hostname) formatted into
// the gokrazy GUID prefix.
func gptPartuuid(hostname string, partition uint16) string {
	h := fnv.New32a()
	h.Write([]byte(hostname))
	return fmt.Sprintf("60c24cc1-f3f9-427a-8199-%08x00%02x", h.Sum32(), partition)
}

func buildTsappImage(t *testing.T) string {
	t.Helper()
	imgPath, err := filepath.Abs("tsapp.img")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(imgPath); err == nil {
		t.Logf("using existing tsapp.img: %s", imgPath)
		return imgPath
	}

	t.Logf("building tsapp.img...")
	cmd := exec.Command("make", "image")
	cmd.Dir, _ = os.Getwd()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("make image: %v", err)
	}
	if _, err := os.Stat(imgPath); err != nil {
		t.Fatalf("tsapp.img not found after build: %v", err)
	}
	return imgPath
}

// serialLog collects serial console output in a thread-safe manner.
type serialLog struct {
	mu    sync.Mutex
	lines []string
}

func (sl *serialLog) add(line string) {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	sl.lines = append(sl.lines, line)
}

func (sl *serialLog) lastN(n int) []string {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	if len(sl.lines) <= n {
		cp := make([]string, len(sl.lines))
		copy(cp, sl.lines)
		return cp
	}
	cp := make([]string, n)
	copy(cp, sl.lines[len(sl.lines)-n:])
	return cp
}

func (sl *serialLog) findLine(pred func(string) bool) bool {
	sl.mu.Lock()
	defer sl.mu.Unlock()
	for _, line := range sl.lines {
		if pred(line) {
			return true
		}
	}
	return false
}

// TestBusyboxInTsapp boots the tsapp image in QEMU and verifies that
// busybox is accessible via the serial console shell. This validates
// that the serial-busybox package's extra files (the busybox binary)
// are properly included in the image by monogok.
func TestBusyboxInTsapp(t *testing.T) {
	if !*runVMTests {
		t.Skip("skipping VM test; set --run-vm-tests to run")
	}

	kernel := findKernelPath(t)
	if _, err := os.Stat(kernel); err != nil {
		t.Skipf("kernel not found at %s: %v", kernel, err)
	}
	t.Logf("kernel: %s", kernel)

	// Read the hostname from config.json to compute the GPT PARTUUID.
	cfgBytes, err := os.ReadFile("tsapp/config.json")
	if err != nil {
		t.Fatalf("reading tsapp/config.json: %v", err)
	}
	var cfg struct {
		Hostname string
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("parsing config.json: %v", err)
	}
	rootParam := fmt.Sprintf("root=PARTUUID=%s/PARTNROFF=1", gptPartuuid(cfg.Hostname, 1))
	t.Logf("root param: %s", rootParam)

	imgPath := buildTsappImage(t)

	// Create a temporary qcow2 overlay so we don't modify the original image.
	tmpDir := t.TempDir()
	disk := filepath.Join(tmpDir, "tsapp-test.qcow2")
	out, err := exec.Command("qemu-img", "create",
		"-f", "qcow2",
		"-F", "raw",
		"-b", imgPath,
		disk).CombinedOutput()
	if err != nil {
		t.Fatalf("qemu-img create: %v, %s", err, out)
	}

	// Set up a Unix socket for the serial console.
	sockPath := filepath.Join(tmpDir, "serial.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Boot QEMU with microvm, explicit kernel, and serial via virtconsole
	// connected to our Unix socket. The kernel sees hvc0 as the console
	// device, and gokrazy uses it for the serial shell.
	cmd := exec.Command("qemu-system-x86_64",
		"-M", "microvm,isa-serial=off",
		"-m", "1G",
		"-nodefaults", "-no-user-config", "-nographic",
		"-kernel", kernel,
		"-append", "console=hvc0 "+rootParam+" ro init=/gokrazy/init panic=10 oops=panic pci=off nousb tsc=unstable clocksource=hpet",
		"-drive", "id=blk0,file="+disk+",format=qcow2",
		"-device", "virtio-blk-device,drive=blk0",
		"-device", "virtio-rng-device",
		"-device", "virtio-serial-device",
		"-chardev", "socket,id=virtiocon0,path="+sockPath+",server=off",
		"-device", "virtconsole,chardev=virtiocon0",
		"-netdev", "user,id=net0",
		"-device", "virtio-net-device,netdev=net0",
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("qemu start: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	// Accept the serial console connection from QEMU.
	ln.(*net.UnixListener).SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept serial connection: %v", err)
	}
	defer conn.Close()

	// Read serial output in a goroutine.
	slog := &serialLog{}
	bootDone := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		var partial string
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				partial += string(buf[:n])
				for {
					idx := strings.IndexByte(partial, '\n')
					if idx < 0 {
						break
					}
					line := strings.TrimRight(partial[:idx], "\r")
					partial = partial[idx+1:]
					slog.add(line)
					t.Logf("serial: %s", line)
					// gokrazy logs socket listener info when boot is done.
					if strings.Contains(line, "listening on") {
						select {
						case <-bootDone:
						default:
							close(bootDone)
						}
					}
				}
			}
			if err != nil {
				if err != io.EOF {
					t.Logf("serial read error: %v", err)
				}
				return
			}
		}
	}()

	// Wait for boot to complete (up to 120 seconds).
	select {
	case <-bootDone:
		t.Logf("boot complete")
	case <-time.After(120 * time.Second):
		t.Fatalf("timeout waiting for boot; last lines:\n%s",
			strings.Join(slog.lastN(20), "\n"))
	}

	// Small delay to let services fully initialize.
	time.Sleep(2 * time.Second)

	// Send a newline to trigger the serial shell.
	// gokrazy's init reads stdin and calls tryStartShell() on any input.
	fmt.Fprintf(conn, "\n")
	time.Sleep(2 * time.Second)

	// Send a command to test busybox. The echo command is a busybox builtin,
	// so if busybox is working, we'll see our marker in the output.
	marker := "BUSYBOX_TEST_OK_12345"
	fmt.Fprintf(conn, "echo %s\n", marker)

	// Wait for our marker in the output (not on the echo command line itself).
	deadline := time.After(15 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout waiting for busybox echo response; busybox binary is likely missing from the image.\n"+
				"This indicates monogok is not copying _gokrazy/extrafiles from serial-busybox.\n"+
				"Last serial lines:\n%s",
				strings.Join(slog.lastN(30), "\n"))
		default:
		}
		time.Sleep(200 * time.Millisecond)
		// Look for the marker on a line by itself (the echo output, not the command).
		if slog.findLine(func(line string) bool {
			return strings.TrimSpace(line) == marker
		}) {
			t.Logf("busybox shell is working: got echo response")
			return // success
		}
	}
}
