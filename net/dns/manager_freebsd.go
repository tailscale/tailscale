// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"fmt"
	"io/ioutil"
	"os"

	"tailscale.com/types/logger"
)

func NewOSConfigurator(logf logger.Logf, _ string) (OSConfigurator, error) {
	bs, err := ioutil.ReadFile("/etc/resolv.conf")
	if os.IsNotExist(err) {
		return newDirectManager(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	switch resolvOwner(bs) {
	case "resolvconf":
		switch resolvconfStyle() {
		case "":
			return newDirectManager(), nil
		case "debian":
			return newDebianResolvconfManager(logf)
		case "openresolv":
			return newOpenresolvManager()
		}
	default:
		return newDirectManager(), nil
	}
}
