// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package docs embeds certain docs, making them available for other packages.
package docs

import _ "embed"

// CommitMessages is the contents of commit-messages.md.
//
//go:embed commit-messages.md
var CommitMessages string
