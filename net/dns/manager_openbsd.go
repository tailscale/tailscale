// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"bytes"
	"fmt"
	"os"

	"tailscale.com/types/logger"
)

type kv struct {
	k, v string
}

func (kv kv) String() string {
	return fmt.Sprintf("%s=%s", kv.k, kv.v)
}

func NewOSConfigurator(logf logger.Logf, interfaceName string) (OSConfigurator, error) {
	return newOSConfigurator(logf, interfaceName,
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

func newOSConfigurator(logf logger.Logf, interfaceName string, env newOSConfigEnv) (ret OSConfigurator, err error) {
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
		return newDirectManager(logf), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	if env.rcIsResolvd(bs) {
		dbg("resolvd", "yes")
		return newResolvdManager(logf, interfaceName)
	}

	dbg("resolvd", "missing")
	return newDirectManager(logf), nil
}

func rcIsResolvd(resolvConfContents []byte) bool {
	// If we have the string "# resolvd:" in resolv.conf resolvd(8) is
	// managing things.
	if bytes.Contains(resolvConfContents, []byte("# resolvd:")) {
		return true
	}
	return false
}
