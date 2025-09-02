// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"bytes"
	"fmt"
	"os"

	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/syspolicy/policyclient"
)

type kv struct {
	k, v string
}

func (kv kv) String() string {
	return fmt.Sprintf("%s=%s", kv.k, kv.v)
}

// NewOSConfigurator created a new OS configurator.
//
// The health tracker may be nil; the knobs may be nil and are ignored on this platform.
func NewOSConfigurator(logf logger.Logf, health *health.Tracker, _ policyclient.Client, _ *controlknobs.Knobs, interfaceName string) (OSConfigurator, error) {
	return newOSConfigurator(logf, health, interfaceName,
		newOSConfigEnv{
			rcIsResolvd: rcIsResolvd,
			fs:          directFS{},
		})
}

// newOSConfigEnv are the funcs newOSConfigurator needs, pulled out for testing.
type newOSConfigEnv struct {
	fs          directFS
	rcIsResolvd func(resolvConfContents []byte) bool
}

func newOSConfigurator(logf logger.Logf, health *health.Tracker, interfaceName string, env newOSConfigEnv) (ret OSConfigurator, err error) {
	var debug []kv
	dbg := func(k, v string) {
		debug = append(debug, kv{k, v})
	}
	defer func() {
		if ret != nil {
			dbg("ret", fmt.Sprintf("%T", ret))
		}
		logf("dns: %v", debug)
	}()

	bs, err := env.fs.ReadFile(resolvConf)
	if os.IsNotExist(err) {
		dbg("rc", "missing")
		return newDirectManager(logf, health), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	if env.rcIsResolvd(bs) {
		dbg("resolvd", "yes")
		return newResolvdManager(logf, interfaceName)
	}

	dbg("resolvd", "missing")
	return newDirectManager(logf, health), nil
}

func rcIsResolvd(resolvConfContents []byte) bool {
	// If we have the string "# resolvd:" in resolv.conf resolvd(8) is
	// managing things.
	if bytes.Contains(resolvConfContents, []byte("# resolvd:")) {
		return true
	}
	return false
}
