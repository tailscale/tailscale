// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build ignore

// The gens.go program generates the feature_<feature>_enabled.go
// and feature_<feature>_disabled.go files for each feature tag.
package main

import (
	"cmp"
	"fmt"
	"os"
	"strings"

	"tailscale.com/feature/featuretags"
	"tailscale.com/util/must"
)

const header = `// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Code g|e|n|e|r|a|t|e|d by gen.go; D|O N|OT E|D|I|T.

`

func main() {
	header := strings.ReplaceAll(header, "|", "") // to avoid this file being marked as generated
	for k, m := range featuretags.Features {
		if !k.IsOmittable() {
			continue
		}
		sym := "Has" + cmp.Or(m.Sym, strings.ToUpper(string(k)[:1])+string(k)[1:])
		for _, suf := range []string{"enabled", "disabled"} {
			bang := ""
			if suf == "enabled" {
				bang = "!" // !ts_omit_...
			}
			must.Do(os.WriteFile("feature_"+string(k)+"_"+suf+".go",
				fmt.Appendf(nil, "%s//go:build %s%s\n\npackage buildfeatures\n\n"+
					"// %s is whether the binary was built with support for modular feature %q.\n"+
					"// Specifically, it's whether the binary was NOT built with the %q build tag.\n"+
					"// It's a const so it can be used for dead code elimination.\n"+
					"const %s = %t\n",
					header, bang, k.OmitTag(), sym, m.Desc, k.OmitTag(), sym, suf == "enabled"), 0644))

		}
	}
}
