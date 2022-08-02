// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import * as qrcode from "qrcode"
import { getContentNode } from "./index"

export async function showLoginURL(url: string) {
  if (loginNode) {
    loginNode.remove()
  }
  loginNode = document.createElement("div")
  loginNode.className = "flex flex-col items-center justify-items-center"
  const linkNode = document.createElement("a")
  linkNode.className = "link"
  linkNode.href = url
  linkNode.target = "_blank"
  loginNode.appendChild(linkNode)

  try {
    const dataURL = await qrcode.toDataURL(url, { width: 512 })
    const imageNode = document.createElement("img")
    imageNode.className = "mx-auto"
    imageNode.src = dataURL
    imageNode.width = 256
    imageNode.height = 256
    linkNode.appendChild(imageNode)
  } catch (err) {
    console.error("Could not generate QR code:", err)
  }

  linkNode.appendChild(document.createTextNode(url))

  getContentNode().appendChild(loginNode)
}

export function hideLoginURL() {
  if (!loginNode) {
    return
  }
  loginNode.remove()
  loginNode = undefined
}

let loginNode: HTMLDivElement | undefined

export function showLogoutButton(ipn: IPN) {
  if (logoutButtonNode) {
    logoutButtonNode.remove()
  }
  logoutButtonNode = document.createElement("button")
  logoutButtonNode.className =
    "button bg-gray-500 border-gray-500 text-white hover:bg-gray-600 hover:border-gray-600 ml-2 font-bold"
  logoutButtonNode.textContent = "Logout"
  logoutButtonNode.addEventListener(
    "click",
    () => {
      ipn.logout()
    },
    { once: true }
  )
  const headerNode = document.getElementsByTagName("header")[0]!
  headerNode.appendChild(logoutButtonNode)
}

export function hideLogoutButton() {
  if (!logoutButtonNode) {
    return
  }
  logoutButtonNode.remove()
  logoutButtonNode = undefined
}

let logoutButtonNode: HTMLButtonElement | undefined
