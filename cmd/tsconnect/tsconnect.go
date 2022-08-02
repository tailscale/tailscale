// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The tsconnect command builds and serves the static site that is generated for
// the Tailscale Connect JS/WASM client. Can be run in 3 modes:
//   - dev: builds the site and serves it. JS and CSS changes can be picked up
//     with a reload.
//   - build: builds the site and writes it to dist/
//   - serve: serves the site from dist/ (embedded in the binary)
package main // import "tailscale.com/cmd/tsconnect"

import (
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	addr     = flag.String("addr", ":9090", "address to listen on")
	distDir  = flag.String("distdir", "./dist", "path of directory to place build output in")
	yarnPath = flag.String("yarnpath", "../../tool/yarn", "path yarn executable used to install JavaScript dependencies")
)

func main() {
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) != 1 {
		flag.Usage()
	}

	switch flag.Arg(0) {
	case "dev":
		runDev()
	case "build":
		runBuild()
	case "serve":
		runServe()
	default:
		log.Printf("Unknown command: %s", flag.Arg(0))
		flag.Usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `
usage: tsconnect {dev|build|serve}
`[1:])

	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `

tsconnect implements development/build/serving workflows for Tailscale Connect.
It can be invoked with one of three subcommands:

- dev: Run in development mode, allowing JS and CSS changes to be picked up without a rebuilt or restart.
- build: Run in production build mode (generating static assets)
- serve: Run in production serve mode (serving static assets)
`[1:])
	os.Exit(2)
}
