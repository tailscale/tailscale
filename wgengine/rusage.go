// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wgengine

import (
	"fmt"
	"runtime"

	"tailscale.com/types/logger"
)

// RusagePrefixLog returns a Logf func wrapping the provided logf func that adds
// a prefixed log message to each line with the current binary memory usage
// and max RSS.
func RusagePrefixLog(logf logger.Logf) logger.Logf {
	return func(f string, argv ...interface{}) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		goMem := float64(m.HeapInuse+m.StackInuse) / (1 << 20)
		maxRSS := rusageMaxRSS()
		pf := fmt.Sprintf("%.1fM/%.1fM %s", goMem, maxRSS, f)
		logf(pf, argv...)
	}
}
