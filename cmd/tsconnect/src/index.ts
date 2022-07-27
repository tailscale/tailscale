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
  // The Go process should never exit, if it does then it's an unhandled panic.
  go.run(result.instance).then(() => handleGoPanic())
  const ipn = newIPN({
    // Persist IPN state in sessionStorage in development, so that we don't need
    // to re-authorize every time we reload the page.
    stateStorage: DEBUG ? sessionStateStorage : undefined,
  })
  ipn.run({
    notifyState: notifyState.bind(null, ipn),
    notifyNetMap: notifyNetMap.bind(null, ipn),
    notifyBrowseToURL: notifyBrowseToURL.bind(null, ipn),
    notifyPanicRecover: handleGoPanic,
  })
})

function handleGoPanic(err?: string) {
  if (DEBUG && err) {
    console.error("Go panic", err)
  }
  if (panicNode) {
    panicNode.remove()
  }
  panicNode = document.createElement("div")
  panicNode.className =
    "rounded bg-red-500 p-2 absolute top-2 right-2 text-white font-bold text-right cursor-pointer"
  panicNode.textContent = "Tailscale has encountered an error."
  const panicDetailNode = document.createElement("div")
  panicDetailNode.className = "text-sm font-normal"
  panicDetailNode.textContent = "Click to reload"
  panicNode.appendChild(panicDetailNode)
  panicNode.addEventListener("click", () => location.reload(), {
    once: true,
  })
  document.body.appendChild(panicNode)
  setTimeout(() => {
    panicNode!.remove()
  }, 10000)
}

let panicNode: HTMLDivElement | undefined
