// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import { useState, useCallback, useMemo, useEffect, useRef } from "preact/hooks"
import { createPortal } from "preact/compat"
import type { VNode } from "preact"
import { runSSHSession, SSHSessionDef } from "../lib/ssh"

export function SSH({ netMap, ipn }: { netMap: IPNNetMap; ipn: IPN }) {
  const [sshSessionDef, setSSHSessionDef] = useState<SSHFormSessionDef | null>(
    null
  )
  const clearSSHSessionDef = useCallback(() => setSSHSessionDef(null), [])
  if (sshSessionDef) {
    const sshSession = (
      <SSHSession def={sshSessionDef} ipn={ipn} onDone={clearSSHSessionDef} />
    )
    if (sshSessionDef.newWindow) {
      return <NewWindow close={clearSSHSessionDef}>{sshSession}</NewWindow>
    }
    return sshSession
  }
  const sshPeers = netMap.peers.filter(
    (p) => p.tailscaleSSHEnabled && p.online !== false
  )

  if (sshPeers.length == 0) {
    return <NoSSHPeers />
  }

  return <SSHForm sshPeers={sshPeers} onSubmit={setSSHSessionDef} />
}

type SSHFormSessionDef = SSHSessionDef & { newWindow?: boolean }

function SSHSession({
  def,
  ipn,
  onDone,
}: {
  def: SSHSessionDef
  ipn: IPN
  onDone: () => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (ref.current) {
      runSSHSession(ref.current, def, ipn, onDone)
    }
  }, [ref])

  return <div class="flex-grow bg-black p-2 overflow-hidden" ref={ref} />
}

function NoSSHPeers() {
  return (
    <div class="container mx-auto px-4 text-center">
      None of your machines have
      <a href="https://tailscale.com/kb/1193/tailscale-ssh/" class="link">
        Tailscale SSH
      </a>
      enabled. Give it a try!
    </div>
  )
}

function SSHForm({
  sshPeers,
  onSubmit,
}: {
  sshPeers: IPNNetMapPeerNode[]
  onSubmit: (def: SSHFormSessionDef) => void
}) {
  sshPeers = sshPeers.slice().sort((a, b) => a.name.localeCompare(b.name))
  const [username, setUsername] = useState("")
  const [hostname, setHostname] = useState(sshPeers[0].name)
  return (
    <form
      class="container mx-auto px-4 flex justify-center"
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit({ username, hostname })
      }}
    >
      <input
        type="text"
        class="input username"
        placeholder="Username"
        onChange={(e) => setUsername(e.currentTarget.value)}
      />
      <div class="select-with-arrow mx-2">
        <select
          class="select"
          onChange={(e) => setHostname(e.currentTarget.value)}
        >
          {sshPeers.map((p) => (
            <option key={p.nodeKey}>{p.name.split(".")[0]}</option>
          ))}
        </select>
      </div>
      <input
        type="submit"
        class="button bg-green-500 border-green-500 text-white hover:bg-green-600 hover:border-green-600"
        value="SSH"
        onClick={(e) => {
          if (e.altKey) {
            e.preventDefault()
            e.stopPropagation()
            onSubmit({ username, hostname, newWindow: true })
          }
        }}
      />
    </form>
  )
}

const NewWindow = ({
  children,
  close,
}: {
  children: VNode
  close: () => void
}) => {
  const newWindow = useMemo(() => {
    const newWindow = window.open(undefined, undefined, "width=600,height=400")
    if (newWindow) {
      const containerNode = newWindow.document.createElement("div")
      containerNode.className = "h-screen flex flex-col overflow-hidden"
      newWindow.document.body.appendChild(containerNode)

      for (const linkNode of document.querySelectorAll(
        "head link[rel=stylesheet]"
      )) {
        const newLink = document.createElement("link")
        newLink.rel = "stylesheet"
        newLink.href = (linkNode as HTMLLinkElement).href
        newWindow.document.head.appendChild(newLink)
      }
    }
    return newWindow
  }, [])
  if (!newWindow) {
    console.error("Could not open window")
    return null
  }
  newWindow.onbeforeunload = () => {
    close()
  }

  useEffect(() => () => newWindow.close(), [])
  return createPortal(children, newWindow.document.body.lastChild as Element)
}
