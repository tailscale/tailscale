// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import * as Control from "src/components/control-components"
import { NodeData, NodeUpdaters } from "src/hooks/node-data"
import Toggle from "src/ui/toggle"

export default function SSHView({
  readonly,
  node,
  nodeUpdaters,
}: {
  readonly: boolean
  node: NodeData
  nodeUpdaters: NodeUpdaters
}) {
  return (
    <>
      <h1 className="mb-1">Tailscale SSH server</h1>
      <p className="description mb-10">
        Run a Tailscale SSH server on this device and allow other devices in
        your tailnet to SSH into it.{" "}
        <a
          href="https://tailscale.com/kb/1193/tailscale-ssh/"
          className="text-indigo-700"
          target="_blank"
          rel="noreferrer"
        >
          Learn more &rarr;
        </a>
      </p>
      <div className="-mx-5 px-4 py-3 bg-white rounded-lg border border-gray-200 flex gap-2.5 mb-3">
        <Toggle
          checked={node.RunningSSHServer}
          onChange={() =>
            nodeUpdaters.patchPrefs({
              RunSSHSet: true,
              RunSSH: !node.RunningSSHServer,
            })
          }
          disabled={readonly}
        />
        <div className="text-black text-sm font-medium leading-tight">
          Run Tailscale SSH server
        </div>
      </div>
      <Control.AdminContainer
        className="text-neutral-500 text-sm leading-tight"
        node={node}
      >
        Remember to make sure that the{" "}
        <Control.AdminLink node={node} path="/acls">
          tailnet policy file
        </Control.AdminLink>{" "}
        allows other devices to SSH into this device.
      </Control.AdminContainer>
    </>
  )
}
