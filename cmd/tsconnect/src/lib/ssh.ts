// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { Terminal, ITerminalOptions } from "xterm"
import { FitAddon } from "xterm-addon-fit"
import { WebLinksAddon } from "xterm-addon-web-links"

export type SSHSessionDef = {
  username: string
  hostname: string
  /** Defaults to 5 seconds */
  timeoutSeconds?: number
}

export type SSHSessionCallbacks = {
  onConnectionProgress: (messsage: string) => void
  onConnected: () => void
  onDone: () => void
  onError?: (err: string) => void
}

export function runSSHSession(
  termContainerNode: HTMLDivElement,
  def: SSHSessionDef,
  ipn: IPN,
  callbacks: SSHSessionCallbacks,
  terminalOptions?: ITerminalOptions
) {
  const parentWindow = termContainerNode.ownerDocument.defaultView ?? window
  const term = new Terminal({
    cursorBlink: true,
    allowProposedApi: true,
    ...terminalOptions,
  })

  const fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(termContainerNode)
  fitAddon.fit()

  const webLinksAddon = new WebLinksAddon((event, uri) =>
    event.view?.open(uri, "_blank", "noopener")
  )
  term.loadAddon(webLinksAddon)

  let onDataHook: ((data: string) => void) | undefined
  term.onData((e) => {
    onDataHook?.(e)
  })

  term.focus()

  let resizeObserver: ResizeObserver | undefined
  let handleUnload: ((e: Event) => void) | undefined

  const sshSession = ipn.ssh(def.hostname, def.username, {
    writeFn(input) {
      term.write(input)
    },
    writeErrorFn(err) {
      callbacks.onError?.(err)
      term.write(err)
    },
    setReadFn(hook) {
      onDataHook = hook
    },
    rows: term.rows,
    cols: term.cols,
    onConnectionProgress: callbacks.onConnectionProgress,
    onConnected: callbacks.onConnected,
    onDone() {
      resizeObserver?.disconnect()
      term.dispose()
      if (handleUnload) {
        parentWindow.removeEventListener("unload", handleUnload)
      }
      callbacks.onDone()
    },
    timeoutSeconds: def.timeoutSeconds,
  })

  // Make terminal and SSH session track the size of the containing DOM node.
  resizeObserver = new parentWindow.ResizeObserver(() => fitAddon.fit())
  resizeObserver.observe(termContainerNode)
  term.onResize(({ rows, cols }) => sshSession.resize(rows, cols))

  // Close the session if the user closes the window without an explicit
  // exit.
  handleUnload = () => sshSession.close()
  parentWindow.addEventListener("unload", handleUnload)
}
