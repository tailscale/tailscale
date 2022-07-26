// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { Terminal } from "xterm"

export function showSSHPeers(peers: IPNNetMapPeerNode[], ipn: IPN) {
  const peersNode = document.getElementById("peers") as HTMLDivElement
  peersNode.innerHTML = ""

  const sshPeers = peers.filter((p) => p.tailscaleSSHEnabled)
  if (!sshPeers.length) {
    peersNode.textContent = "No machines have Tailscale SSH installed."
    return
  }

  for (const peer of sshPeers) {
    const peerNode = document.createElement("div")
    peerNode.className = "peer"
    const nameNode = document.createElement("div")
    nameNode.className = "name"
    nameNode.textContent = peer.name
    peerNode.appendChild(nameNode)

    const sshButtonNode = document.createElement("button")
    sshButtonNode.className = "ssh"
    sshButtonNode.addEventListener("click", function () {
      ssh(peer.name, ipn)
    })
    sshButtonNode.textContent = "SSH"
    peerNode.appendChild(sshButtonNode)

    peersNode.appendChild(peerNode)
  }
}

export function hideSSHPeers() {
  const peersNode = document.getElementById("peers") as HTMLDivElement
  peersNode.innerHTML = ""
}

function ssh(hostname: string, ipn: IPN) {
  const termContainerNode = document.createElement("div")
  termContainerNode.className = "term-container"
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

  ipn.ssh(
    hostname,
    (input) => term.write(input),
    (hook) => (onDataHook = hook),
    term.rows,
    term.cols,
    () => {
      term.dispose()
      termContainerNode.remove()
    }
  )
}
