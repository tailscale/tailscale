// Package build provides the build artifacts for the web client.
package build

import (
	"embed"
)

//go:embed index.html all:assets
var FS embed.FS
