// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hostinfo answers questions about the host environment that Tailscale is
// running on.
package hostinfo

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/lineread"
	"tailscale.com/version"
)

// New returns a partially populated Hostinfo for the current host.
func New() *tailcfg.Hostinfo {
	hostname, _ := os.Hostname()
	hostname = dnsname.FirstLabel(hostname)
	return &tailcfg.Hostinfo{
		IPNVersion:  version.Long,
		Hostname:    hostname,
		OS:          version.OS(),
		OSVersion:   GetOSVersion(),
		Package:     packageType(),
		GoArch:      runtime.GOARCH,
		DeviceModel: deviceModel(),
	}
}

var osVersion func() string // non-nil on some platforms

// GetOSVersion returns the OSVersion of current host if available.
func GetOSVersion() string {
	if s, _ := osVersionAtomic.Load().(string); s != "" {
		return s
	}
	if osVersion != nil {
		return osVersion()
	}
	return ""
}

func packageType() (ret string) {
	if v, _ := packagingType.Load().(string); v != "" {
		return v
	}
	switch runtime.GOOS {
	case "windows":
		defer func() {
			if ret != "" {
				packagingType.Store(ret)
			}
		}()
		if _, err := os.Stat(`C:\ProgramData\chocolatey\lib\tailscale`); err == nil {
			return "choco"
		}
		exe, err := os.Executable()
		if err != nil {
			return ""
		}
		dir := filepath.Dir(exe)
		if !strings.Contains(dir, "Program Files") {
			// Atypical. Not worth trying to detect. Likely open
			// source tailscaled or a developer running by hand.
			return ""
		}
		nsisUninstaller := filepath.Join(dir, "Uninstall-Tailscale.exe")
		_, err = os.Stat(nsisUninstaller)
		if err == nil {
			return "nsis"
		}
		if os.IsNotExist(err) {
			_, cliErr := os.Stat(filepath.Join(dir, "tailscale.exe"))
			_, daemonErr := os.Stat(filepath.Join(dir, "tailscaled.exe"))
			if cliErr == nil && daemonErr == nil {
				// Almost certainly MSI.
				// We have tailscaled.exe and tailscale.exe
				// next to each other in Program Files, but no
				// uninstaller.
				// TODO(bradfitz,dblohm7): tighter heuristic?
				return "msi"
			}
		}
	case "darwin":
		// Using tailscaled or IPNExtension?
		exe, _ := os.Executable()
		return filepath.Base(exe)
	case "linux":
		// Report whether this is in a snap.
		// See https://snapcraft.io/docs/environment-variables
		// We just look at two somewhat arbitrarily.
		if os.Getenv("SNAP_NAME") != "" && os.Getenv("SNAP") != "" {
			return "snap"
		}
	}
	return ""
}

// EnvType represents a known environment type.
// The empty string, the default, means unknown.
type EnvType string

const (
	KNative         = EnvType("kn")
	AWSLambda       = EnvType("lm")
	Heroku          = EnvType("hr")
	AzureAppService = EnvType("az")
	AWSFargate      = EnvType("fg")
	FlyDotIo        = EnvType("fly")
	Kubernetes      = EnvType("k8s")
	DockerDesktop   = EnvType("dde")
)

var envType atomic.Value // of EnvType

func GetEnvType() EnvType {
	if e, ok := envType.Load().(EnvType); ok {
		return e
	}
	e := getEnvType()
	envType.Store(e)
	return e
}

var (
	deviceModelAtomic atomic.Value // of string
	osVersionAtomic   atomic.Value // of string
	packagingType     atomic.Value // of string
)

// SetDeviceModel sets the device model for use in Hostinfo updates.
func SetDeviceModel(model string) { deviceModelAtomic.Store(model) }

// SetOSVersion sets the OS version.
func SetOSVersion(v string) { osVersionAtomic.Store(v) }

// SetPackage sets the packaging type for the app.
// This is currently (2021-10-05) only used by Android,
// set to "nogoogle" for the F-Droid build.
func SetPackage(v string) { packagingType.Store(v) }

func deviceModel() string {
	s, _ := deviceModelAtomic.Load().(string)
	return s
}

func getEnvType() EnvType {
	if inKnative() {
		return KNative
	}
	if inAWSLambda() {
		return AWSLambda
	}
	if inHerokuDyno() {
		return Heroku
	}
	if inAzureAppService() {
		return AzureAppService
	}
	if inAWSFargate() {
		return AWSFargate
	}
	if inFlyDotIo() {
		return FlyDotIo
	}
	if inKubernetes() {
		return Kubernetes
	}
	if inDockerDesktop() {
		return DockerDesktop
	}
	return ""
}

// inContainer reports whether we're running in a container.
func inContainer() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	var ret bool
	lineread.File("/proc/1/cgroup", func(line []byte) error {
		if mem.Contains(mem.B(line), mem.S("/docker/")) ||
			mem.Contains(mem.B(line), mem.S("/lxc/")) {
			ret = true
			return io.EOF // arbitrary non-nil error to stop loop
		}
		return nil
	})
	lineread.File("/proc/mounts", func(line []byte) error {
		if mem.Contains(mem.B(line), mem.S("fuse.lxcfs")) {
			ret = true
			return io.EOF
		}
		return nil
	})
	return ret
}

func inKnative() bool {
	// https://cloud.google.com/run/docs/reference/container-contract#env-vars
	if os.Getenv("K_REVISION") != "" && os.Getenv("K_CONFIGURATION") != "" &&
		os.Getenv("K_SERVICE") != "" && os.Getenv("PORT") != "" {
		return true
	}
	return false
}

func inAWSLambda() bool {
	// https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
	if os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != "" &&
		os.Getenv("AWS_LAMBDA_FUNCTION_VERSION") != "" &&
		os.Getenv("AWS_LAMBDA_INITIALIZATION_TYPE") != "" &&
		os.Getenv("AWS_LAMBDA_RUNTIME_API") != "" {
		return true
	}
	return false
}

func inHerokuDyno() bool {
	// https://devcenter.heroku.com/articles/dynos#local-environment-variables
	if os.Getenv("PORT") != "" && os.Getenv("DYNO") != "" {
		return true
	}
	return false
}

func inAzureAppService() bool {
	if os.Getenv("APPSVC_RUN_ZIP") != "" && os.Getenv("WEBSITE_STACK") != "" &&
		os.Getenv("WEBSITE_AUTH_AUTO_AAD") != "" {
		return true
	}
	return false
}

func inAWSFargate() bool {
	if os.Getenv("AWS_EXECUTION_ENV") == "AWS_ECS_FARGATE" {
		return true
	}
	return false
}

func inFlyDotIo() bool {
	if os.Getenv("FLY_APP_NAME") != "" && os.Getenv("FLY_REGION") != "" {
		return true
	}
	return false
}

func inKubernetes() bool {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" && os.Getenv("KUBERNETES_SERVICE_PORT") != "" {
		return true
	}
	return false
}

func inDockerDesktop() bool {
	if os.Getenv("TS_HOST_ENV") == "dde" {
		return true
	}
	return false
}

type etcAptSrcResult struct {
	mod      time.Time
	disabled bool
}

var etcAptSrcCache atomic.Value // of etcAptSrcResult

// DisabledEtcAptSource reports whether Ubuntu (or similar) has disabled
// the /etc/apt/sources.list.d/tailscale.list file contents upon upgrade
// to a new release of the distro.
//
// See https://github.com/tailscale/tailscale/issues/3177
func DisabledEtcAptSource() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	const path = "/etc/apt/sources.list.d/tailscale.list"
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	mod := fi.ModTime()
	if c, ok := etcAptSrcCache.Load().(etcAptSrcResult); ok && c.mod == mod {
		return c.disabled
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	v := etcAptSourceFileIsDisabled(f)
	etcAptSrcCache.Store(etcAptSrcResult{mod: mod, disabled: v})
	return v
}

func etcAptSourceFileIsDisabled(r io.Reader) bool {
	bs := bufio.NewScanner(r)
	disabled := false // did we find the "disabled on upgrade" comment?
	for bs.Scan() {
		line := strings.TrimSpace(bs.Text())
		if strings.Contains(line, "# disabled on upgrade") {
			disabled = true
		}
		if line == "" || line[0] == '#' {
			continue
		}
		// Well, it has some contents in it at least.
		return false
	}
	return disabled
}
