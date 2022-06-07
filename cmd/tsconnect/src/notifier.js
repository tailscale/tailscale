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

/**
 * @fileoverview Notification callback functions (bridged from ipn.Notify)
 */

/** Mirrors values from ipn/backend.go */
const State = {
  NoState: 0,
  InUseOtherUser: 1,
  NeedsLogin: 2,
  NeedsMachineAuth: 3,
  Stopped: 4,
  Starting: 5,
  Running: 6,
}

export function notifyState(ipn, state) {
  let stateLabel
  switch (state) {
    case State.NoState:
      stateLabel = "Initializing…"
      break
    case State.InUseOtherUser:
      stateLabel = "In-use by another user"
      break
    case State.NeedsLogin:
      stateLabel = "Needs Login"
      hideLogoutButton()
      hideSSHPeers()
      ipn.login()
      break
    case State.NeedsMachineAuth:
      stateLabel = "Needs authorization"
      break
    case State.Stopped:
      stateLabel = "Stopped"
      hideLogoutButton()
      hideSSHPeers()
      break
    case State.Starting:
      stateLabel = "Starting…"
      break
    case State.Running:
      stateLabel = "Running"
      hideLoginURL()
      showLogoutButton(ipn)
      break
  }
  const stateNode = document.getElementById("state")
  stateNode.textContent = stateLabel ?? ""
}

export function notifyNetMap(ipn, netMapStr) {
  const netMap = JSON.parse(netMapStr)
  if (DEBUG) {
    console.log("Received net map: " + JSON.stringify(netMap, null, 2))
  }

  showSSHPeers(netMap.peers, ipn)
}

export function notifyBrowseToURL(ipn, url) {
  showLoginURL(url)
}
