// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package dns

import (
	"regexp"
	"strings"
)

// parseIni parses a basic .ini file, used for wsl.conf.
func parseIni(data string) map[string]map[string]string {
	sectionRE := regexp.MustCompile(`^\[([^]]+)\]`)
	kvRE := regexp.MustCompile(`^\s*(\w+)\s*=\s*([^#]*)`)

	ini := map[string]map[string]string{}
	var section string
	for _, line := range strings.Split(data, "\n") {
		if res := sectionRE.FindStringSubmatch(line); len(res) > 1 {
			section = res[1]
			ini[section] = map[string]string{}
		} else if res := kvRE.FindStringSubmatch(line); len(res) > 2 {
			k, v := strings.TrimSpace(res[1]), strings.TrimSpace(res[2])
			ini[section][k] = v
		}
	}
	return ini
}
