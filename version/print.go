// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
)

var stringLazy = sync.OnceValue(func() string {
	var ret strings.Builder
	ret.WriteString(Short())
	ret.WriteByte('\n')
	if IsUnstableBuild() {
		fmt.Fprintf(&ret, "  track: unstable (dev); frequent updates and bugs are likely\n")
	}
	if gitCommit() != "" {
		fmt.Fprintf(&ret, "  tailscale commit: %s%s\n", gitCommit(), dirtyString())
	}
	fmt.Fprintf(&ret, "  long version: %s\n", Long())
	if extraGitCommitStamp != "" {
		fmt.Fprintf(&ret, "  other commit: %s\n", extraGitCommitStamp)
	}
	if tsGoRev := tailscaleToolchainRev(); tsGoRev != "" {
		if len(tsGoRev) > 10 {
			tsGoRev = tsGoRev[:10]
		}
		fmt.Fprintf(&ret, "  go version: %s (tailscale/go %s)\n", runtime.Version(), tsGoRev)
	} else {
		fmt.Fprintf(&ret, "  go version: %s\n", runtime.Version())
	}
	return strings.TrimSpace(ret.String())
})

func String() string {
	return stringLazy()
}
