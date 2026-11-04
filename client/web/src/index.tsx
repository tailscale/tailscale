// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Preserved js license comment for web client app.
/**
 * @license
 * Copyright (c) Tailscale Inc & contributors
 * SPDX-License-Identifier: BSD-3-Clause
 */

import React from "react"
import { createRoot } from "react-dom/client"
import { swrConfig } from "src/api"
import App from "src/components/app"
import { I18nProvider } from "src/i18n"
import ToastProvider from "src/ui/toaster"
import { SWRConfig } from "swr"

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
    <SWRConfig value={swrConfig}>
      <I18nProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </I18nProvider>
    </SWRConfig>
  </React.StrictMode>
)
