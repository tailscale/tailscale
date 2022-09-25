// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Type definitions need to be manually imported for dts-bundle-generator to
// discover them.
/// <reference path="../types/esbuild.d.ts" />
/// <reference path="../types/wasm_js.d.ts" />

import "../wasm_exec"
import wasmURL from "./main.wasm"

/**
 * Superset of the IPNConfig type, with additional configuration that is
 * needed for the package to function.
 */
type IPNPackageConfig = IPNConfig & {
  // Auth key used to intitialize the Tailscale client (required)
  authKey: string
  // URL of the main.wasm file that is included in the page, if it is not
  // accessible via a relative URL.
  wasmURL?: string
  // Function invoked if the Go process panics or unexpectedly exits.
  panicHandler: (err: string) => void
}

export async function createIPN(config: IPNPackageConfig): Promise<IPN> {
  const go = new Go()
  const wasmInstance = await WebAssembly.instantiateStreaming(
    fetch(config.wasmURL ?? wasmURL),
    go.importObject
  )
  // The Go process should never exit, if it does then it's an unhandled panic.
  go.run(wasmInstance.instance).then(() =>
    config.panicHandler("Unexpected shutdown")
  )

  return newIPN(config)
}

export { runSSHSession } from "../lib/ssh"
