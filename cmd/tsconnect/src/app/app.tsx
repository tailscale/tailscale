// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
          An administrator needs to authorize this device.
        </div>
      )
    }

    let ssh
    if (ipn && ipnState === "Running" && netMap) {
      ssh = <SSH netMap={netMap} ipn={ipn} />
    }

    return (
      <>
        <Header state={ipnState} ipn={ipn} />
        {goPanicDisplay}
        <div class="flex-grow flex flex-col justify-center overflow-hidden">
          {urlDisplay}
          {machineAuthInstructions}
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
