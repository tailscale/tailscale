// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import {
  showLoginURL,
  hideLoginURL,
  showLogoutButton,
  hideLogoutButton,
} from "./login"
import { showSSHPeers, hideSSHPeers } from "./ssh"
import { IPNState } from "./wasm_js"

/**
 * @fileoverview Notification callback functions (bridged from ipn.Notify)
 */

export function notifyState(ipn: IPN, state: IPNState) {
  let stateLabel
  switch (state) {
    case IPNState.NoState:
      stateLabel = "Initializing…"
      break
    case IPNState.InUseOtherUser:
      stateLabel = "In-use by another user"
      break
    case IPNState.NeedsLogin:
      stateLabel = "Needs Login"
      hideLogoutButton()
      hideSSHPeers()
      ipn.login()
      break
    case IPNState.NeedsMachineAuth:
      stateLabel = "Needs authorization"
      break
    case IPNState.Stopped:
      stateLabel = "Stopped"
      hideLogoutButton()
      hideSSHPeers()
      break
    case IPNState.Starting:
      stateLabel = "Starting…"
      break
    case IPNState.Running:
      stateLabel = "Running"
      hideLoginURL()
      showLogoutButton(ipn)
      break
  }
  const stateNode = document.getElementById("state") as HTMLDivElement
  stateNode.textContent = stateLabel ?? ""
}

export function notifyNetMap(ipn: IPN, netMapStr: string) {
  const netMap = JSON.parse(netMapStr) as IPNNetMap
  if (DEBUG) {
    console.log("Received net map: " + JSON.stringify(netMap, null, 2))
  }

  showSSHPeers(netMap.peers, ipn)
}

export function notifyBrowseToURL(ipn: IPN, url: string) {
  showLoginURL(url)
}
