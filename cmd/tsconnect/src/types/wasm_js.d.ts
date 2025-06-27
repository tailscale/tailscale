// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

/**
 * @fileoverview Type definitions for types exported by the wasm_js.go Go
 * module.
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
        writeErrorFn: (err: string) => void
        setReadFn: (readFn: (data: string) => void) => void
        rows: number
        cols: number
        /** Defaults to 5 seconds */
        timeoutSeconds?: number
        onConnectionProgress: (message: string) => void
        onConnected: () => void
        onDone: () => void
      }
    ): IPNSSHSession
    fetch(url: string): Promise<{
      status: number
      statusText: string
      text: () => Promise<string>
    }>
  }

  interface IPNSSHSession {
    resize(rows: number, cols: number): boolean
    close(): boolean
  }

  interface IPNStateStorage {
    setState(id: string, value: string): void
    getState(id: string): string
  }

  type IPNConfig = {
    stateStorage?: IPNStateStorage
    authKey?: string
    controlURL?: string
    hostname?: string
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
    lockedOut: boolean
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

  /** Mirrors values from ipn/backend.go */
  type IPNState =
    | "NoState"
    | "InUseOtherUser"
    | "NeedsLogin"
    | "NeedsMachineAuth"
    | "Stopped"
    | "Starting"
    | "Running"

  /** Mirrors values from MachineStatus in tailcfg.go */
  type IPNMachineStatus =
    | "MachineUnknown"
    | "MachineUnauthorized"
    | "MachineAuthorized"
    | "MachineInvalid"
}

export {}
