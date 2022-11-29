// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package version

var (
	ExportParse          = parse
	ExportFindModuleInfo = findModuleInfo
	ExportCmdName        = cmdName
)

type (
	ExportParsed = parsed
)
