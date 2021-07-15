// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux

package vms

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"tailscale.com/types/logger"
)

// mkVM makes a KVM-accelerated virtual machine and prepares it for introduction
// to the testcontrol server. The function it returns is for killing the virtual
// machine when it is time for it to die.
func (h *Harness) mkVM(t *testing.T, n int, d Distro, sshKey, hostURL, tdir string) {
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

	mkLayeredQcow(t, tdir, d, h.fetchDistro(t, d))
	mkSeed(t, d, sshKey, hostURL, tdir, port)

	driveArg := fmt.Sprintf("file=%s,if=virtio", filepath.Join(tdir, d.name+".qcow2"))

	args := []string{
		"-machine", "pc-q35-5.1,accel=kvm,usb=off,vmport=off,dump-guest-core=off",
		"-netdev", fmt.Sprintf("user,hostfwd=::%d-:22,id=net0", port),
		"-device", "virtio-net-pci,netdev=net0,id=net0,mac=8a:28:5c:30:1f:25",
		"-m", fmt.Sprint(d.mem),
		"-boot", "c",
		"-drive", driveArg,
		"-cdrom", filepath.Join(tdir, d.name, "seed", "seed.iso"),
		"-smbios", "type=1,serial=ds=nocloud;h=" + d.name,
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
	cmd.Stdout = logger.FuncWriter(t.Logf)
	cmd.Stderr = logger.FuncWriter(t.Logf)
	err = cmd.Start()

	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)

	// NOTE(Xe): In Unix if you do a kill with signal number 0, the kernel will do
	// all of the access checking for the process (existence, permissions, etc) but
	// nothing else. This is a way to ensure that qemu's process is active.
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("qemu is not running: %v", err)
	}

	t.Cleanup(func() {
		err := cmd.Process.Kill()
		if err != nil {
			t.Errorf("can't kill %s (%d): %v", d.name, cmd.Process.Pid, err)
		}

		cmd.Wait()
	})
}

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

	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	})
	if err != nil {
		t.Logf("can't make AWS session: %v", err)
		return false
	}

	dler := s3manager.NewDownloader(sess, func(d *s3manager.Downloader) {
		d.PartSize = 64 * 1024 * 1024 // 64MB per part
	})

	t.Logf("fetching s3://%s/%s", bucketName, d.sha256sum)

	_, err = dler.Download(fout, &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(d.sha256sum),
	})
	if err != nil {
		fout.Close()
		t.Fatalf("can't get s3://%s/%s: %v", bucketName, d.sha256sum, err)
	}

	err = fout.Close()
	if err != nil {
		t.Fatalf("can't close fout: %v", err)
	}

	return true
}

// fetchDistro fetches a distribution from the internet if it doesn't already exist locally. It
// also validates the sha256 sum from a known good hash.
func (h *Harness) fetchDistro(t *testing.T, resultDistro Distro) string {
	t.Helper()

	cdir, err := os.UserCacheDir()
	if err != nil {
		t.Fatalf("can't find cache dir: %v", err)
	}
	cdir = filepath.Join(cdir, "tailscale", "vm-test")

	if strings.HasPrefix(resultDistro.name, "nixos") {
		return h.makeNixOSImage(t, resultDistro, cdir)
	}

	qcowPath := filepath.Join(cdir, "qcow2", resultDistro.sha256sum)

	_, err = os.Stat(qcowPath)
	if err == nil {
		hash := checkCachedImageHash(t, resultDistro, cdir)
		if hash != resultDistro.sha256sum {
			t.Logf("hash for %s (%s) doesn't match expected %s, re-downloading", resultDistro.name, qcowPath, resultDistro.sha256sum)
			err = errors.New("some fake non-nil error to force a redownload")

			if err := os.Remove(qcowPath); err != nil {
				t.Fatalf("can't delete wrong cached image: %v", err)
			}
		}
	}

	if err != nil {
		t.Logf("downloading distro image %s to %s", resultDistro.url, qcowPath)
		fout, err := os.Create(qcowPath)
		if err != nil {
			t.Fatal(err)
		}

		if !fetchFromS3(t, fout, resultDistro) {
			resp, err := http.Get(resultDistro.url)
			if err != nil {
				t.Fatalf("can't fetch qcow2 for %s (%s): %v", resultDistro.name, resultDistro.url, err)
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				t.Fatalf("%s replied %s", resultDistro.url, resp.Status)
			}

			_, err = io.Copy(fout, resp.Body)
			if err != nil {
				t.Fatalf("download of %s failed: %v", resultDistro.url, err)
			}

			resp.Body.Close()
			err = fout.Close()
			if err != nil {
				t.Fatalf("can't close fout: %v", err)
			}

			hash := checkCachedImageHash(t, resultDistro, cdir)

			if hash != resultDistro.sha256sum {
				t.Fatalf("hash mismatch, want: %s, got: %s", resultDistro.sha256sum, hash)
			}
		}
	}

	return qcowPath
}

func checkCachedImageHash(t *testing.T, d Distro, cacheDir string) (gotHash string) {
	t.Helper()

	qcowPath := filepath.Join(cacheDir, "qcow2", d.sha256sum)

	fin, err := os.Open(qcowPath)
	if err != nil {
		t.Fatal(err)
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, fin); err != nil {
		t.Fatal(err)
	}
	hash := hex.EncodeToString(hasher.Sum(nil))

	if hash != d.sha256sum {
		t.Fatalf("hash mismatch, got: %q, want: %q", hash, d.sha256sum)
	}

	gotHash = hash

	return
}

func (h *Harness) copyBinaries(t *testing.T, d Distro, conn *ssh.Client) {
	bins := h.bins
	if strings.HasPrefix(d.name, "nixos") {
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

	copyFile(t, cli, bins.Daemon, "/usr/sbin/tailscaled")
	copyFile(t, cli, bins.CLI, "/usr/bin/tailscale")

	// TODO(Xe): revisit this assumption before it breaks the test.
	copyFile(t, cli, "../../../cmd/tailscaled/tailscaled.defaults", "/etc/default/tailscaled")

	switch d.initSystem {
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
