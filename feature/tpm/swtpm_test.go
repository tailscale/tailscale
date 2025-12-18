// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build linux && ts_swtpm

package tpm

import (
	"bytes"
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// swtpmBinary is the name of the swtpm executable to use
const swtpmBinary = "swtpm"
const example32ByteKey = "12345678901234567890123456789012"

type swtpm struct {
	dataDir    string
	deviceName string
	devicePath string
	pidFile    string
	opts       *swtpmOptions
	t          testing.TB
}

func newSWTPM(t testing.TB, opts ...swtpmOption) *swtpm {
	t.Helper()
	options := &swtpmOptions{
		version: "2.0",
	}

	for _, opt := range opts {
		opt(options)
	}

	dataDir := t.TempDir()

	suffix := make([]byte, 8)
	if _, err := crand.Read(suffix); err != nil {
		t.Fatalf("failed to generate random suffix: %v", err)
	}

	// use unique per-test vtpm device names to avoid conflicts
	deviceName := fmt.Sprintf("vtpm-%d-%s", time.Now().UnixNano(), hex.EncodeToString(suffix))
	devicePath := filepath.Join("/dev", deviceName)
	pidFile := filepath.Join(dataDir, "swtpm.pid")

	s := &swtpm{
		dataDir:    dataDir,
		deviceName: deviceName,
		devicePath: devicePath,
		pidFile:    pidFile,
		opts:       options,
		t:          t,
	}
	s.t.Logf("created swtpm with device %s, data dir %s", deviceName, dataDir)

	if err := s.start(); err != nil {
		t.Fatalf("failed to start swtpm: %v", err)
	}

	t.Cleanup(func() {
		s.stop()
	})

	return s
}

// runSetup initializes the TPM state using swtpm_setup
func (s *swtpm) runSetup() error {
	args := []string{
		"--tpmstate", s.dataDir,
	}

	switch s.opts.version {
	case "1.2":
		// TPM 1.2 is the default for swtpm_setup, no flag needed
	case "2.0":
		args = append(args, "--tpm2")
	default:
		s.t.Fatalf("unsupported swtpm version for setup: %q", s.opts.version)
	}

	fullArgs := append([]string{"swtpm_setup"}, args...)
	cmd := exec.Command("sudo", fullArgs...)
	s.t.Logf("running swtpm_setup with args: %v", args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swtpm_setup failed: %w: %s", err, output)
	} else {
		s.t.Logf("swtpm_setup output: %s", output)
	}

	return nil
}

// start launches the swtpm process with the configured options
func (s *swtpm) start() error {
	// init state if requested
	if s.opts.withSetup {
		if err := s.runSetup(); err != nil {
			return fmt.Errorf("swtpm_setup failed: %w", err)
		}
	}

	args := []string{
		"cuse",
		"--tpmstate", fmt.Sprintf("dir=%s", s.dataDir),
		"--name", s.deviceName,
		"--pid", fmt.Sprintf("file=%s", s.pidFile),
	}

	switch s.opts.version {
	case "1.2":
	case "2.0":
		args = append(args, "--tpm2")
	default:
		return fmt.Errorf("unsupported swtpm version: %s", s.opts.version)
	}

	// when using swtpm_setup, we need to tell swtpm to send TPM2_Startup(CLEAR)
	if s.opts.withSetup {
		args = append(args, "--flags", "startup-clear")
	}

	if s.opts.flags != nil {
		args = append(args, s.opts.flags...)
	}

	fullArgs := append([]string{swtpmBinary}, args...)
	cmd := exec.Command("sudo", fullArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start swtpm with args %v: %w: %s", args, err, out)
	} else {
		s.t.Logf("swtpm started with args %v output: %s", args, out)
	}

	s.t.Logf("waiting for swtpm device at %s", s.devicePath)
	if err := s.waitForDevice(); err != nil {
		s.stop()
		return fmt.Errorf("swtpm device not available: %w", err)
	} else {
		s.t.Logf("swtpm device available at %s", s.devicePath)
	}

	return nil
}

// waitForDevice waits for the swtpm character device to be created
func (s *swtpm) waitForDevice() error {
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for device at %s", s.devicePath)
		case <-ticker.C:
			if _, err := os.Stat(s.devicePath); err == nil {
				return nil
			}
		}
	}
}

// stop terminates the swtpm process and cleans up resources
func (s *swtpm) stop() {
	pidBytes, err := os.ReadFile(s.pidFile)
	if err != nil {
		s.t.Logf("failed to read swtpm pid file %s: %v", s.pidFile, err)
		return
	}

	var pid int
	pid, err = strconv.Atoi(string(bytes.TrimSpace(pidBytes)))
	if err != nil {
		s.t.Logf("failed to parse swtpm pid %q: %v", string(pidBytes), err)
		return
	}
	var process *os.Process
	process, err = os.FindProcess(pid)
	if err != nil {
		s.t.Logf("failed to find swtpm process with pid %d: %v", pid, err)
		return
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		s.t.Logf("failed to send SIGTERM to swtpm PID %d: %v", pid, err)
		return
	}
	s.t.Logf("sent SIGTERM to swtpm PID %d", pid)

	done := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			s.t.Logf("swtpm PID %d exited with error: %v", pid, err)
		} else {
			s.t.Logf("swtpm PID %d exited after SIGTERM", pid)
		}
	case <-time.After(2 * time.Second):
		s.t.Fatalf("timed out waiting for process %d to terminate", pid)
	}
}

// DevicePath returns the path to the swtpm character device
func (s *swtpm) DevicePath() string {
	return s.devicePath
}

type swtpmOptions struct {
	version   string
	flags     []string
	withSetup bool
}

type swtpmOption func(*swtpmOptions)

// withSetup enables TPM initialization via swtpm_setup
func withSetup() swtpmOption {
	return func(o *swtpmOptions) {
		o.withSetup = true
	}
}

// withSwtpmVersion sets the TPM version (either "1.2" or "2.0")
func withSwtpmVersion(version string) swtpmOption {
	return func(o *swtpmOptions) {
		o.version = version
	}
}

// withTPM12 configures swtpm to use TPM 1.2
func withTPM12() swtpmOption {
	return withSwtpmVersion("1.2")
}

// withTPM20 configures swtpm to use TPM 2.0 (default)
func withTPM20() swtpmOption {
	return withSwtpmVersion("2.0")
}

// checkSWTPMAvailable checks if swtpm is available and errors if not
func checkSWTPMAvailable(t testing.TB) {
	t.Helper()
	p, err := exec.LookPath(swtpmBinary)
	if err != nil {
		t.Fatalf("swtpm binary not found in PATH: %v", err)
		return
	}

	// ensure version 0.10.1
	cmd := exec.Command(p, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to execute swtpm --version: %v", err)
		return
	}

	if !bytes.HasPrefix(output, []byte("TPM emulator version 0.10.1")) {
		t.Fatalf("swtpm version is not compatible: %s", output)
		return
	}

	// ensure that we can run swtpm with sudo non-interactive (necessary to create CUSE devices)
	cmd = exec.Command("sudo", "-n", p, "cuse", "--help")
	if err := cmd.Run(); err != nil {
		t.Fatalf("swtpm cannot be run with sudo without password prompt: %v", err)
	}
}

func TestSWTPM_Integration(t *testing.T) {
	checkSWTPMAvailable(t)

	tests := []struct {
		name    string
		opts    []swtpmOption
		wantErr bool
	}{
		{
			name:    "broken-1.2-no-setup",
			opts:    []swtpmOption{withTPM12()},
			wantErr: true,
		},
		{
			name:    "broken-2.0-no-setup",
			opts:    []swtpmOption{withTPM20()},
			wantErr: true,
		},
		{
			name: "working-2.0",
			opts: []swtpmOption{withTPM20(), withSetup()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swtpm := newSWTPM(t, tt.opts...)
			devicePath := swtpm.DevicePath()

			if _, err := os.Stat(devicePath); err != nil {
				t.Fatalf("swtpm device does not exist at %s: %v", devicePath, err)
			}

			tpmDev, err := linuxtpm.Open(devicePath)
			if err != nil {
				t.Fatalf("linuxtpm.Open(%s) failed: %v", devicePath, err)
			}
			defer tpmDev.Close()

			err = withSRK(t.Logf, tpmDev, func(srk tpm2.AuthHandle) error {
				t.Logf("Successfully loaded SRK with handle: %v", srk.Handle)
				return nil
			})

			if tt.wantErr != (err != nil) {
				t.Errorf("withSRK() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestSWTPM_SealUnseal(t *testing.T) {
	checkSWTPMAvailable(t)

	tests := []struct {
		name    string
		opts    []swtpmOption
		data    []byte
		wantErr bool
	}{
		{
			name:    "1.2-fail-no-setup",
			opts:    []swtpmOption{withTPM12()},
			data:    []byte(example32ByteKey),
			wantErr: true,
		},
		{
			name:    "1.2-fail-32-byte-key",
			opts:    []swtpmOption{withTPM12(), withSetup()},
			data:    []byte(example32ByteKey),
			wantErr: true,
		},
		{
			name:    "2.0-seal-fail-no-setup",
			opts:    []swtpmOption{withTPM20()},
			data:    []byte("test data"),
			wantErr: true,
		},
		{
			name:    "2.0-seal-unseal-32-byte-key",
			opts:    []swtpmOption{withTPM20(), withSetup()},
			data:    []byte(example32ByteKey),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			swtpm := newSWTPM(t, tt.opts...)
			devicePath := swtpm.DevicePath()

			tpmDev, err := linuxtpm.Open(devicePath)
			if err != nil {
				t.Fatalf("linuxtpm.Open(%s) failed: %v", devicePath, err)
			}
			defer tpmDev.Close()

			sealed, err := tpmSealWithTPM(t.Logf, tpmDev, tt.data)
			if tt.wantErr {
				if err == nil {
					t.Errorf("tpmSealWithTPM() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("tpmSealWithTPM() failed: %v", err)
			}

			if sealed == nil {
				t.Fatal("tpmSealWithTPM() returned nil sealed data")
			}
			if len(sealed.Private) == 0 {
				t.Error("sealed.Private is empty")
			}
			if len(sealed.Public) == 0 {
				t.Error("sealed.Public is empty")
			}

			unsealed, err := tpmUnsealWithTPM(t.Logf, tpmDev, sealed)
			if err != nil {
				t.Fatalf("tpmUnsealWithTPM() failed: %v", err)
			}

			if !bytes.Equal(unsealed, tt.data) {
				t.Errorf("unsealed data mismatch:\ngot:  %q\nwant: %q", unsealed, tt.data)
			}
		})
	}
}

func TestSWTPM_SealUnsealCrossDevice(t *testing.T) {
	checkSWTPMAvailable(t)

	swtpm1 := newSWTPM(t, withTPM20(), withSetup())
	tpmDev1, err := linuxtpm.Open(swtpm1.DevicePath())
	if err != nil {
		t.Fatalf("linuxtpm.Open(%s) failed: %v", swtpm1.DevicePath(), err)
	}
	defer tpmDev1.Close()

	logf := func(format string, args ...any) {
		t.Logf(format, args...)
	}

	testData := []byte("TPM1 secret data")
	sealed, err := tpmSealWithTPM(logf, tpmDev1, testData)
	if err != nil {
		t.Fatalf("tpmSealWithTPM() on first device failed: %v", err)
	}

	// round trip on the same TPM
	unsealed, err := tpmUnsealWithTPM(logf, tpmDev1, sealed)
	if err != nil {
		t.Fatalf("tpmUnsealWithTPM() on first device failed: %v", err)
	}
	if !bytes.Equal(unsealed, testData) {
		t.Errorf("unsealed data mismatch on first device:\ngot:  %q\nwant: %q", unsealed, testData)
	}

	// create a second device
	swtpm2 := newSWTPM(t, withTPM20(), withSetup())
	tpmDev2, err := linuxtpm.Open(swtpm2.DevicePath())
	if err != nil {
		t.Fatalf("linuxtpm.Open(%s) failed: %v", swtpm2.DevicePath(), err)
	}
	defer tpmDev2.Close()

	// confirm we cannot unseal with the second TPM
	_, err = tpmUnsealWithTPM(logf, tpmDev2, sealed)
	if err == nil {
		t.Error("tpmUnsealWithTPM() on second device should have failed but succeeded")
	}
}
