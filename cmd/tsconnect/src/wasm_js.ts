// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/**
 * @fileoverview Type definitions for types exported by the wasm_js.go Go
 * module. Not actually a .d.ts file so that we can use enums from it in
 * esbuild's simplified TypeScript compiler (see https://github.com/evanw/esbuild/issues/2298#issuecomment-1146378367)
 */

declare global {
  function newIPN(config: IPNConfig): IPN

  interface IPN {
    run(callbacks: IPNCallbacks): void
    login(): void
    logout(): void
    ssh(
      host: string,
      username: string,
      termConfig: {
        writeFn: (data: string) => void
        setReadFn: (readFn: (data: string) => void) => void
        rows: number
        cols: number
        onDone: () => void
      }
    ): void
  }

  interface IPNStateStorage {
    setState(id: string, value: string): void
    getState(id: string): string
  }

  type IPNConfig = {
    stateStorage?: IPNStateStorage
  }

  type IPNCallbacks = {
    notifyState: (state: IPNState) => void
    notifyNetMap: (netMapStr: string) => void
    notifyBrowseToURL: (url: string) => void
    notifyPanicRecover: (err: string) => void
  }

  type IPNNetMap = {
    self: IPNNetMapSelfNode
    peers: IPNNetMapPeerNode[]
  }

  type IPNNetMapNode = {
    name: string
    addresses: string[]
    machineKey: string
    nodeKey: string
  }

  type IPNNetMapSelfNode = IPNNetMapNode & {
    machineStatus: IPNMachineStatus
  }

  type IPNNetMapPeerNode = IPNNetMapNode & {
    online?: boolean
    tailscaleSSHEnabled: boolean
  }
}

/** Mirrors values from ipn/backend.go */
export const enum IPNState {
  NoState = 0,
  InUseOtherUser = 1,
  NeedsLogin = 2,
  NeedsMachineAuth = 3,
  Stopped = 4,
  Starting = 5,
  Running = 6,
}

/** Mirrors values from MachineStatus in tailcfg.go */
export const enum IPNMachineStatus {
  MachineUnknown = 0,
  MachineUnauthorized = 1,
  MachineAuthorized = 2,
  MachineInvalid = 3,
}
