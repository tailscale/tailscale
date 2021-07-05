// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hostinfo answers questions about the host environment that Tailscale is
// running on.
//
// TODO(bradfitz): move more of control/controlclient/hostinfo_* into this package.
package hostinfo

import (
	"flag"
	"io"
	"os"
	"runtime"
	"sync/atomic"

	"go4.org/mem"
	"tailscale.com/util/lineread"
)

// EnvType represents a known environment type.
// The empty string, the default, means unknown.
type EnvType string

const (
	KNative         = EnvType("kn")
	AWSLambda       = EnvType("lm")
	Heroku          = EnvType("hr")
	AzureAppService = EnvType("az")
	AWSFargate      = EnvType("fg")
	TestCase        = EnvType("tc")
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

func getEnvType() EnvType {
	// inTestCase needs to go first. If running tests in a container, we want
	// the environment to be TestCase not the type of container.
	if inTestCase() {
		return TestCase
	}
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
	return ""
}

// InContainer reports whether we're running in a container.
func InContainer() bool {
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

func inTestCase() bool {
	if flag.CommandLine.Lookup("test.v") != nil {
		return true
	}
	return false
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
