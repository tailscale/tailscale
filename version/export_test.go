// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package version

var (
	ExportParse          = parse
	ExportFindModuleInfo = findModuleInfo
	ExportCmdName        = cmdName
)

type (
	ExportParsed = parsed
)
