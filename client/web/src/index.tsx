// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Preserved js license comment for web client app.
/**
 * @license
 * Copyright (c) Tailscale Inc & AUTHORS
 * SPDX-License-Identifier: BSD-3-Clause
 */

import React from "react"
import { createRoot } from "react-dom/client"
import App from "src/components/app"
import { SWRConfig } from "swr"
import { apiFetch } from "./api"

declare var window: any
// This is used to determine if the react client is built.
window.Tailscale = true

const rootEl = document.createElement("div")
rootEl.id = "app-root"
rootEl.classList.add("relative", "z-0")
document.body.append(rootEl)

const root = createRoot(rootEl)

root.render(
  <React.StrictMode>
    <SWRConfig
      value={{
        fetcher: apiFetch,
        onError: (err, _) => {
          // TODO: toast on error instead?
          if (err.message) {
            alert(`Request failed: ${err.message}`)
          }
          console.error(err)
        },
      }}
    >
      <App />
    </SWRConfig>
  </React.StrictMode>
)
