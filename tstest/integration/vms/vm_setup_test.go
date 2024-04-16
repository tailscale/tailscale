// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows && !plan9

package vms

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"tailscale.com/types/logger"
)

type vmInstance struct {
	d       Distro
	cmd     *exec.Cmd
	done    chan struct{}
	doneErr error // not written until done is closed
}

func (vm *vmInstance) running() bool {
	select {
	case <-vm.done:
		return false
	default:
		return true
	}
}

func (vm *vmInstance) waitStartup(t *testing.T) {
	t.Helper()
	for range 100 {
		if vm.running() {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !vm.running() {
		t.Fatal("vm not running")
	}
}

func (h *Harness) makeImage(t *testing.T, d Distro, cdir string) string {
	if !strings.HasPrefix(d.Name, "nixos") {
		t.Fatal("image generation for non-nixos is not implemented")
	}
	return h.makeNixOSImage(t, d, cdir)
}

// mkVM makes a KVM-accelerated virtual machine and prepares it for introduction
// to the testcontrol server. The function it returns is for killing the virtual
// machine when it is time for it to die.
func (h *Harness) mkVM(t *testing.T, n int, d Distro, sshKey, hostURL, tdir string) *vmInstance {
	t.Helper()

	cdir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("can't find cache dir: %v", err)
	}
	cdir = filepath.Join(cdir, "tailscale", "vm-test")
	os.MkdirAll(filepath.Join(cdir, "qcow2"), 0755)

	port, err := getProbablyFreePortNumber()
	if err != nil {
		t.Fatal(err)
	}

	var qcowPath string
	if d.HostGenerated {
		qcowPath = h.makeImage(t, d, cdir)
	} else {
		qcowPath = fetchDistro(t, d)
	}

	mkLayeredQcow(t, tdir, d, qcowPath)
	mkSeed(t, d, sshKey, hostURL, tdir, port)

	driveArg := fmt.Sprintf("file=%s,if=virtio", filepath.Join(tdir, d.Name+".qcow2"))

	args := []string{
		"-machine", "q35,accel=kvm,usb=off,vmport=off,dump-guest-core=off",
		"-netdev", fmt.Sprintf("user,hostfwd=::%d-:22,id=net0", port),
		"-device", "virtio-net-pci,netdev=net0,id=net0,mac=8a:28:5c:30:1f:25",
		"-m", fmt.Sprint(d.MemoryMegs),
		"-cpu", "host",
		"-smp", "4",
		"-boot", "c",
		"-drive", driveArg,
		"-cdrom", filepath.Join(tdir, d.Name, "seed", "seed.iso"),
		"-smbios", "type=1,serial=ds=nocloud;h=" + d.Name,
		"-nographic",
	}

	if *useVNC {
		// test listening on VNC port
		ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", strconv.Itoa(5900+n)))
		if err != nil {
			t.Fatalf("would not be able to listen on the VNC port for the VM: %v", err)
		}
		ln.Close()
		args = append(args, "-vnc", fmt.Sprintf(":%d", n))
	} else {
		args = append(args, "-display", "none")
	}

	t.Logf("running: qemu-system-x86_64 %s", strings.Join(args, " "))

	cmd := exec.Command("qemu-system-x86_64", args...)
	cmd.Stdout = &qemuLog{f: t.Logf}
	cmd.Stderr = &qemuLog{f: t.Logf}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	vm := &vmInstance{
		cmd:  cmd,
		d:    d,
		done: make(chan struct{}),
	}

	go func() {
		vm.doneErr = cmd.Wait()
		close(vm.done)
	}()
	t.Cleanup(func() {
		err := vm.cmd.Process.Kill()
		if err != nil {
			t.Logf("can't kill %s (%d): %v", d.Name, cmd.Process.Pid, err)
		}
		<-vm.done
	})

	return vm
}

type qemuLog struct {
	buf []byte
	f   logger.Logf
}

func (w *qemuLog) Write(p []byte) (int, error) {
	if !*verboseQemu {
		return len(p), nil
	}
	w.buf = append(w.buf, p...)
	if i := bytes.LastIndexByte(w.buf, '\n'); i > 0 {
		j := i
		if w.buf[j-1] == '\r' {
			j--
		}
		buf := ansiEscCodeRE.ReplaceAll(w.buf[:j], nil)
		w.buf = w.buf[i+1:]

		w.f("qemu console: %q", buf)
	}
	return len(p), nil
}

var ansiEscCodeRE = regexp.MustCompile("\x1b" + `\[[0-?]*[ -/]*[@-~]`)

// fetchFromS3 fetches a distribution image from Amazon S3 or reports whether
// it is unable to. It can fail to fetch from S3 if there is either no AWS
// configuration (in ~/.aws/credentials) or if the `-no-s3` flag is passed. In
// that case the test will fall back to downloading distribution images from the
// public internet.
//
// Like fetching from HTTP, the test will fail if an error is encountered during
// the downloading process.
//
// This function writes the distribution image to fout. It is always closed. Do
// not expect fout to remain writable.
func fetchFromS3(t *testing.T, fout *os.File, d Distro) bool {
	t.Helper()

	if *noS3 {
		t.Log("you asked to not use S3, not using S3")
		return false
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-1"))
	if err != nil {
		t.Logf("can't load AWS credentials: %v", err)
		return false
	}

	dler := manager.NewDownloader(s3.NewFromConfig(cfg), func(d *manager.Downloader) {
		d.PartSize = 64 * 1024 * 1024 // 64MB per part
	})

	t.Logf("fetching s3://%s/%s", bucketName, d.SHA256Sum)

	_, err = dler.Download(context.TODO(), fout, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(d.SHA256Sum),
	})
	if err != nil {
		fout.Close()
		t.Fatalf("can't get s3://%s/%s: %v", bucketName, d.SHA256Sum, err)
	}

	err = fout.Close()
	if err != nil {
		t.Fatalf("can't close fout: %v", err)
	}

	return true
}

// fetchDistro fetches a distribution from the internet if it doesn't already exist locally. It
// also validates the sha256 sum from a known good hash.
func fetchDistro(t *testing.T, resultDistro Distro) string {
	t.Helper()

	cdir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("can't find cache dir: %v", err)
	}
	cdir = filepath.Join(cdir, "tailscale", "vm-test")

	qcowPath := filepath.Join(cdir, "qcow2", resultDistro.SHA256Sum)

	if _, err = os.Stat(qcowPath); err == nil {
		hash := checkCachedImageHash(t, resultDistro, cdir)
		if hash == resultDistro.SHA256Sum {
			return qcowPath
		}
		t.Logf("hash for %s (%s) doesn't match expected %s, re-downloading", resultDistro.Name, qcowPath, resultDistro.SHA256Sum)
		if err := os.Remove(qcowPath); err != nil {
			t.Fatalf("can't delete wrong cached image: %v", err)
		}
	}

	t.Logf("downloading distro image %s to %s", resultDistro.URL, qcowPath)
	if err := os.MkdirAll(filepath.Dir(qcowPath), 0777); err != nil {
		t.Fatal(err)
	}
	fout, err := os.Create(qcowPath)
	if err != nil {
		t.Fatal(err)
	}

	if !fetchFromS3(t, fout, resultDistro) {
		resp, err := http.Get(resultDistro.URL)
		if err != nil {
			t.Fatalf("can't fetch qcow2 for %s (%s): %v", resultDistro.Name, resultDistro.URL, err)
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("%s replied %s", resultDistro.URL, resp.Status)
		}

		if n, err := io.Copy(fout, resp.Body); err != nil {
			t.Fatalf("download of %s failed: %v", resultDistro.URL, err)
		} else if n == 0 {
			t.Fatalf("download of %s got zero-length file", resultDistro.URL)
		}

		resp.Body.Close()
		if err = fout.Close(); err != nil {
			t.Fatalf("can't close fout: %v", err)
		}

		hash := checkCachedImageHash(t, resultDistro, cdir)

		if hash != resultDistro.SHA256Sum {
			t.Fatalf("hash mismatch for %s, want: %s, got: %s", resultDistro.URL, resultDistro.SHA256Sum, hash)
		}
	}

	return qcowPath
}

func checkCachedImageHash(t *testing.T, d Distro, cacheDir string) string {
	t.Helper()

	qcowPath := filepath.Join(cacheDir, "qcow2", d.SHA256Sum)

	fin, err := os.Open(qcowPath)
	if err != nil {
		t.Fatal(err)
	}
	defer fin.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, fin); err != nil {
		t.Fatal(err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	if hash != d.SHA256Sum {
		t.Fatalf("hash mismatch, got: %q, want: %q", hash, d.SHA256Sum)
	}
	return hash
}

func (h *Harness) copyBinaries(t *testing.T, d Distro, conn *ssh.Client) {
	if strings.HasPrefix(d.Name, "nixos") {
		return
	}

	cli, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatalf("can't connect over sftp to copy binaries: %v", err)
	}

	mkdir(t, cli, "/usr/bin")
	mkdir(t, cli, "/usr/sbin")
	mkdir(t, cli, "/etc/default")
	mkdir(t, cli, "/var/lib/tailscale")

	copyFile(t, cli, h.daemon, "/usr/sbin/tailscaled")
	copyFile(t, cli, h.cli, "/usr/bin/tailscale")

	// TODO(Xe): revisit this assumption before it breaks the test.
	copyFile(t, cli, "../../../cmd/tailscaled/tailscaled.defaults", "/etc/default/tailscaled")

	switch d.InitSystem {
	case "openrc":
		mkdir(t, cli, "/etc/init.d")
		copyFile(t, cli, "../../../cmd/tailscaled/tailscaled.openrc", "/etc/init.d/tailscaled")
	case "systemd":
		mkdir(t, cli, "/etc/systemd/system")
		copyFile(t, cli, "../../../cmd/tailscaled/tailscaled.service", "/etc/systemd/system/tailscaled.service")
	}

	fout, err := cli.OpenFile("/etc/default/tailscaled", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatalf("can't append to defaults for tailscaled: %v", err)
	}
	fmt.Fprintf(fout, "\n\nTS_LOG_TARGET=%s\n", h.loginServerURL)
	fout.Close()

	t.Log("tailscale installed!")
}

func mkdir(t *testing.T, cli *sftp.Client, name string) {
	t.Helper()

	err := cli.MkdirAll(name)
	if err != nil {
		t.Fatalf("can't make %s: %v", name, err)
	}
}

func copyFile(t *testing.T, cli *sftp.Client, localSrc, remoteDest string) {
	t.Helper()

	fin, err := os.Open(localSrc)
	if err != nil {
		t.Fatalf("can't open: %v", err)
	}
	defer fin.Close()

	fi, err := fin.Stat()
	if err != nil {
		t.Fatalf("can't stat: %v", err)
	}

	fout, err := cli.Create(remoteDest)
	if err != nil {
		t.Fatalf("can't create output file: %v", err)
	}

	err = fout.Chmod(fi.Mode())
	if err != nil {
		fout.Close()
		t.Fatalf("can't chmod fout: %v", err)
	}

	n, err := io.Copy(fout, fin)
	if err != nil {
		fout.Close()
		t.Fatalf("copy failed: %v", err)
	}

	if fi.Size() != n {
		t.Fatalf("incorrect number of bytes copied: wanted: %d, got: %d", fi.Size(), n)
	}

	err = fout.Close()
	if err != nil {
		t.Fatalf("can't close fout on remote host: %v", err)
	}
}

const metaDataTemplate = `instance-id: {{.ID}}
local-hostname: {{.Hostname}}`

const userDataTemplate = `#cloud-config
#vim:syntax=yaml

cloud_config_modules:
 - runcmd

cloud_final_modules:
 - [users-groups, always]
 - [scripts-user, once-per-instance]

users:
 - name: root
   ssh-authorized-keys:
    - {{.SSHKey}}
 - name: ts
   plain_text_passwd: {{.Password}}
   groups: [ wheel ]
   sudo: [ "ALL=(ALL) NOPASSWD:ALL" ]
   shell: /bin/sh
   ssh-authorized-keys:
    - {{.SSHKey}}

write_files:
  - path: /etc/cloud/cloud.cfg.d/80_disable_network_after_firstboot.cfg
    content: |
      # Disable network configuration after first boot
      network:
        config: disabled

runcmd:
{{.InstallPre}}
 - [ curl, "{{.HostURL}}/myip/{{.Port}}", "-H", "User-Agent: {{.Hostname}}" ]
`
