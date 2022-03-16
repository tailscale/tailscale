// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

import (
	"fmt"
	"runtime"
	"strings"
)

func String() string {
	var ret strings.Builder
	ret.WriteString(Short)
	ret.WriteByte('\n')
	if GitCommit != "" {
		var dirty string
		if GitDirty {
			dirty = "-dirty"
		}
		fmt.Fprintf(&ret, "  tailscale commit: %s%s\n", GitCommit, dirty)
	}
	if ExtraGitCommit != "" {
		fmt.Fprintf(&ret, "  other commit: %s\n", ExtraGitCommit)
	}
	fmt.Fprintf(&ret, "  go version: %s\n", runtime.Version())
	return strings.TrimSpace(ret.String())
}
