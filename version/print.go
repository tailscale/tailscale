// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"fmt"
	"runtime"
	"strings"
)

func String() string {
	var ret strings.Builder
	ret.WriteString(short)
	ret.WriteByte('\n')
	if IsUnstableBuild() {
		fmt.Fprintf(&ret, "  track: unstable (dev); frequent updates and bugs are likely\n")
	}
	if gitCommit != "" {
		var dirty string
		if gitDirty {
			dirty = "-dirty"
		}
		fmt.Fprintf(&ret, "  tailscale commit: %s%s\n", gitCommit, dirty)
	}
	if extraGitCommit != "" {
		fmt.Fprintf(&ret, "  other commit: %s\n", extraGitCommit)
	}
	fmt.Fprintf(&ret, "  go version: %s\n", runtime.Version())
	return strings.TrimSpace(ret.String())
}
