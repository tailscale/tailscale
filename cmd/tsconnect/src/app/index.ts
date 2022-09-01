// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import "../wasm_exec"
import wasmUrl from "./main.wasm"
import { sessionStateStorage } from "../lib/js-state-store"
import { renderApp } from "./app"

async function main() {
  const app = await renderApp()
  const go = new Go()
  const wasmInstance = await WebAssembly.instantiateStreaming(
    fetch(`./dist/${wasmUrl}`),
    go.importObject
  )
  // The Go process should never exit, if it does then it's an unhandled panic.
  go.run(wasmInstance.instance).then(() =>
    app.handleGoPanic("Unexpected shutdown")
  )

  const params = new URLSearchParams(window.location.search)
  const authKey = params.get("authkey") ?? undefined

  const ipn = newIPN({
    // Persist IPN state in sessionStorage in development, so that we don't need
    // to re-authorize every time we reload the page.
    stateStorage: DEBUG ? sessionStateStorage : undefined,
    // authKey allows for an auth key to be
    // specified as a url param which automatically
    // authorizes the client for use.
    authKey: DEBUG ? authKey : undefined,
  })
  app.runWithIPN(ipn)
}

main()
