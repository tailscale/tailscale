// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { Terminal } from "xterm"

export function showSSHForm(peers: IPNNetMapPeerNode[], ipn: IPN) {
  const formNode = document.getElementById("ssh-form") as HTMLDivElement
  const noSSHNode = document.getElementById("no-ssh") as HTMLDivElement

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
  const formNode = document.getElementById("ssh-form") as HTMLDivElement
  formNode.classList.add("hidden")
}

function ssh(hostname: string, username: string, ipn: IPN) {
  const termContainerNode = document.createElement("div")
  termContainerNode.className = "p-3"
  document.body.appendChild(termContainerNode)

  const term = new Terminal({
    cursorBlink: true,
  })
  term.open(termContainerNode)

  // Cancel wheel events from scrolling the page if the terminal has scrollback
  termContainerNode.addEventListener("wheel", (e) => {
    if (term.buffer.active.baseY > 0) {
      e.preventDefault()
    }
  })

  let onDataHook: ((data: string) => void) | undefined
  term.onData((e) => {
    onDataHook?.(e)
  })

  term.focus()

  ipn.ssh(hostname, username, {
    writeFn: (input) => term.write(input),
    setReadFn: (hook) => (onDataHook = hook),
    rows: term.rows,
    cols: term.cols,
    onDone: () => {
      term.dispose()
      termContainerNode.remove()
    },
  })
}
