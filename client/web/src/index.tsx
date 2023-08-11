import React from "react"
import { createRoot } from "react-dom/client"
import App from "src/components/app"

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
