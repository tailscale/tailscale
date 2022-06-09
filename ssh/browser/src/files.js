// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

export function handleFile(file) {
  const fileNode = document.createElement("div")
  fileNode.addEventListener("click", () => fileNode.remove(), { once: true })
  fileNode.className = "file"
  fileNode.appendChild(document.createTextNode("Received file: "))

  const linkNode = document.createElement("a")
  linkNode.href = `data:;base64,${file.data}`
  linkNode.download = file.name
  linkNode.textContent = file.name
  fileNode.appendChild(linkNode)

  document.getElementById("files").appendChild(fileNode)
}
