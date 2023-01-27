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
	ret.WriteString(Short)
	ret.WriteByte('\n')
	if IsUnstableBuild() {
		fmt.Fprintf(&ret, "  track: unstable (dev); frequent updates and bugs are likely\n")
	}
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
