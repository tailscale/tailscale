// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import "./wasm_exec"
import wasmUrl from "./main.wasm"
import { notifyState, notifyNetMap, notifyBrowseToURL } from "./notifier"
import { sessionStateStorage } from "./js-state-store"

const go = new Go()
WebAssembly.instantiateStreaming(
  fetch(`./dist/${wasmUrl}`),
  go.importObject
).then((result) => {
  go.run(result.instance)
  const ipn = newIPN({
    // Persist IPN state in sessionStorage in development, so that we don't need
    // to re-authorize every time we reload the page.
    stateStorage: DEBUG ? sessionStateStorage : undefined,
  })
  ipn.run({
    notifyState: notifyState.bind(null, ipn),
    notifyNetMap: notifyNetMap.bind(null, ipn),
    notifyBrowseToURL: notifyBrowseToURL.bind(null, ipn),
  })
})
