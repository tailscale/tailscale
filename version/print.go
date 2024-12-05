// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package version

import (
	"fmt"
	"runtime"
	"strings"

	"tailscale.com/types/lazy"
)

var stringLazy = lazy.SyncFunc(func() string {
	var ret strings.Builder
	ret.WriteString(Short())
	ret.WriteByte('\n')
	if IsUnstableBuild() {
		fmt.Fprintf(&ret, "  track: unstable (dev); frequent updates and bugs are likely\n")
	}
	if gitCommit() != "" {
		fmt.Fprintf(&ret, "  tailscale commit: %s%s\n", gitCommit(), dirtyString())
	}
	if extraGitCommitStamp != "" {
		fmt.Fprintf(&ret, "  other commit: %s\n", extraGitCommitStamp)
	}
	fmt.Fprintf(&ret, "  go version: %s\n", runtime.Version())
	return strings.TrimSpace(ret.String())
})

func String() string {
	return stringLazy()
}
