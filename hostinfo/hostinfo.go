// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hostinfo answers questions about the host environment that Tailscale is
// running on.
package hostinfo

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"

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
		OSVersion:   getOSVersion(),
		Package:     packageType(),
		GoArch:      runtime.GOARCH,
		DeviceModel: deviceModel(),
	}
}

var osVersion func() string // non-nil on some platforms

func getOSVersion() string {
	if s, _ := osVersionAtomic.Load().(string); s != "" {
		return s
	}
	if osVersion != nil {
		return osVersion()
	}
	return ""
}

func packageType() string {
	switch runtime.GOOS {
	case "windows":
		if _, err := os.Stat(`C:\ProgramData\chocolatey\lib\tailscale`); err == nil {
			return "choco"
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
)

// SetDeviceModel sets the device model for use in Hostinfo updates.
func SetDeviceModel(model string) { deviceModelAtomic.Store(model) }

// SetOSVersion sets the OS version.
func SetOSVersion(v string) { osVersionAtomic.Store(v) }

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
