// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { Terminal } from "xterm"
import { FitAddon } from "xterm-addon-fit"
import { getContentNode } from "./index"

export function showSSHForm(peers: IPNNetMapPeerNode[], ipn: IPN) {
  const formNode = document.querySelector("#ssh-form") as HTMLDivElement
  const noSSHNode = document.querySelector("#no-ssh") as HTMLDivElement

  const sshPeers = peers.filter(
    (p) => p.tailscaleSSHEnabled && p.online !== false
  )
  if (sshPeers.length == 0) {
    formNode.classList.add("hidden")
    noSSHNode.classList.remove("hidden")
    return
  }
  sshPeers.sort((a, b) => a.name.localeCompare(b.name))

  const selectNode = formNode.querySelector("select")!
  selectNode.innerHTML = ""
  for (const p of sshPeers) {
    const option = document.createElement("option")
    option.textContent = p.name.split(".")[0]
    option.value = p.name
    selectNode.appendChild(option)
  }

  const usernameNode = formNode.querySelector(".username") as HTMLInputElement
  formNode.onsubmit = (e) => {
    e.preventDefault()
    const hostname = selectNode.value
    ssh(hostname, usernameNode.value, ipn)
  }

  noSSHNode.classList.add("hidden")
  formNode.classList.remove("hidden")
}

export function hideSSHForm() {
  const formNode = document.querySelector("#ssh-form") as HTMLDivElement
  formNode.classList.add("hidden")
}

function ssh(hostname: string, username: string, ipn: IPN) {
  document.body.classList.add("ssh-active")
  const termContainerNode = document.createElement("div")
  termContainerNode.className = "flex-grow bg-black p-2 overflow-hidden"
  getContentNode().appendChild(termContainerNode)

  const term = new Terminal({
    cursorBlink: true,
  })
  const fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(termContainerNode)
  fitAddon.fit()

  let onDataHook: ((data: string) => void) | undefined
  term.onData((e) => {
    onDataHook?.(e)
  })

  term.focus()

  const sshSession = ipn.ssh(hostname, username, {
    writeFn: (input) => term.write(input),
    setReadFn: (hook) => (onDataHook = hook),
    rows: term.rows,
    cols: term.cols,
    onDone: () => {
      resizeObserver.disconnect()
      term.dispose()
      termContainerNode.remove()
      document.body.classList.remove("ssh-active")
      window.removeEventListener("beforeunload", beforeUnloadListener)
    },
  })

  // Make terminal and SSH session track the size of the containing DOM node.
  const resizeObserver = new ResizeObserver((entries) => {
    fitAddon.fit()
  })
  resizeObserver.observe(termContainerNode)
  term.onResize(({ rows, cols }) => {
    sshSession.resize(rows, cols)
  })

  // Close the session if the user closes the window without an explicit
  // exit.
  const beforeUnloadListener = () => {
    sshSession.close()
  }
  window.addEventListener("beforeunload", beforeUnloadListener)
}
