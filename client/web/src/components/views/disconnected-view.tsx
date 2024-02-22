// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import TailscaleIcon from "src/assets/icons/tailscale-icon.svg?react"

/**
 * DisconnectedView is rendered after node logout.
 */
export default function DisconnectedView() {
  return (
    <>
      <TailscaleIcon className="mx-auto" />
      <p className="mt-12 text-center text-text-muted">
        You logged out of this device. To reconnect it you will have to
        re-authenticate the device from either the Tailscale app or the
        Tailscale command line interface.
      </p>
    </>
  )
}
