import React from "react"
import { createRoot } from "react-dom/client"
import App from "src/components/app"

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
    <App />
  </React.StrictMode>
)
