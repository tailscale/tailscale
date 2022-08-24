// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

export function Header({ state, ipn }: { state: IPNState; ipn?: IPN }) {
  const stateText = STATE_LABELS[state]

  let logoutButton
  if (state === "Running") {
    logoutButton = (
      <button
        class="button bg-gray-500 border-gray-500 text-white hover:bg-gray-600 hover:border-gray-600 ml-2 font-bold"
        onClick={() => ipn?.logout()}
      >
        Logout
      </button>
    )
  }
  return (
    <div class="bg-gray-100 border-b border-gray-200 pt-4 pb-2">
      <header class="container mx-auto px-4 flex flex-row items-center">
        <h1 class="text-3xl font-bold grow">Tailscale Connect</h1>
        <div class="text-gray-600">{stateText}</div>
        {logoutButton}
      </header>
    </div>
  )
}

const STATE_LABELS = {
  NoState: "Initializing…",
  InUseOtherUser: "In-use by another user",
  NeedsLogin: "Needs login",
  NeedsMachineAuth: "Needs authorization",
  Stopped: "Stopped",
  Starting: "Starting…",
  Running: "Running",
} as const
