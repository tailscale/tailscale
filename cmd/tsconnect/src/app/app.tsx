// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { render, Component } from "preact"
import { URLDisplay } from "./url-display"
import { Header } from "./header"
import { GoPanicDisplay } from "./go-panic-display"
import { SSH } from "./ssh"

type AppState = {
  ipn?: IPN
  ipnState: IPNState
  netMap?: IPNNetMap
  browseToURL?: string
  goPanicError?: string
}

class App extends Component<{}, AppState> {
  state: AppState = { ipnState: "NoState" }
  #goPanicTimeout?: number

  render() {
    const { ipn, ipnState, goPanicError, netMap, browseToURL } = this.state

    let goPanicDisplay
    if (goPanicError) {
      goPanicDisplay = (
        <GoPanicDisplay error={goPanicError} dismiss={this.clearGoPanic} />
      )
    }

    let urlDisplay
    if (browseToURL) {
      urlDisplay = <URLDisplay url={browseToURL} />
    }

    let machineAuthInstructions
    if (ipnState === "NeedsMachineAuth") {
      machineAuthInstructions = (
        <div class="container mx-auto px-4 text-center">
          An administrator needs to approve this device.
        </div>
      )
    }

    const lockedOut = netMap?.lockedOut
    let lockedOutInstructions
    if (lockedOut) {
      lockedOutInstructions = (
        <div class="container mx-auto px-4 text-center space-y-4">
          <p>This instance of Tailscale Connect needs to be signed, due to
            {" "}<a href="https://tailscale.com/kb/1226/tailnet-lock/" class="link">tailnet lock</a>{" "}
            being enabled on this domain.
          </p>

          <p>
            Run the following command on a device with a trusted tailnet lock key:
            <pre>tailscale lock sign {netMap.self.nodeKey}</pre>
          </p>
        </div>
      )
    }

    let ssh
    if (ipn && ipnState === "Running" && netMap && !lockedOut) {
      ssh = <SSH netMap={netMap} ipn={ipn} />
    }

    return (
      <>
        <Header state={ipnState} ipn={ipn} />
        {goPanicDisplay}
        <div class="flex-grow flex flex-col justify-center overflow-hidden">
          {urlDisplay}
          {machineAuthInstructions}
          {lockedOutInstructions}
          {ssh}
        </div>
      </>
    )
  }

  runWithIPN(ipn: IPN) {
    this.setState({ ipn }, () => {
      ipn.run({
        notifyState: this.handleIPNState,
        notifyNetMap: this.handleNetMap,
        notifyBrowseToURL: this.handleBrowseToURL,
        notifyPanicRecover: this.handleGoPanic,
      })
    })
  }

  handleIPNState = (state: IPNState) => {
    const { ipn } = this.state
    this.setState({ ipnState: state })
    if (state === "NeedsLogin") {
      ipn?.login()
    } else if (["Running", "NeedsMachineAuth"].includes(state)) {
      this.setState({ browseToURL: undefined })
    }
  }

  handleNetMap = (netMapStr: string) => {
    const netMap = JSON.parse(netMapStr) as IPNNetMap
    if (DEBUG) {
      console.log("Received net map: " + JSON.stringify(netMap, null, 2))
    }
    this.setState({ netMap })
  }

  handleBrowseToURL = (url: string) => {
    if (this.state.ipnState === "Running") {
      // Ignore URL requests if we're already running -- it's most likely an
      // SSH check mode trigger and we already linkify the displayed URL
      // in the terminal.
      return
    }
    this.setState({ browseToURL: url })
  }

  handleGoPanic = (error: string) => {
    if (DEBUG) {
      console.error("Go panic", error)
    }
    this.setState({ goPanicError: error })
    if (this.#goPanicTimeout) {
      window.clearTimeout(this.#goPanicTimeout)
    }
    this.#goPanicTimeout = window.setTimeout(this.clearGoPanic, 10000)
  }

  clearGoPanic = () => {
    window.clearTimeout(this.#goPanicTimeout)
    this.#goPanicTimeout = undefined
    this.setState({ goPanicError: undefined })
  }
}

export function renderApp(): Promise<App> {
  return new Promise((resolve) => {
    render(
      <App ref={(app) => (app ? resolve(app) : undefined)} />,
      document.body
    )
  })
}
