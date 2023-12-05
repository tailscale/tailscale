// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { isPromise } from "src/utils/util"

/**
 * copyText copies text to the clipboard, handling cross-browser compatibility
 * issues with different clipboard APIs.
 *
 * To support copying after running a network request (eg. generating an invite),
 * pass a promise that resolves to the text to copy.
 *
 * @example
 * copyText("Hello, world!")
 * copyText(generateInvite().then(res => res.data.inviteCode))
 */
export function copyText(text: string | Promise<string | void>) {
  if (!navigator.clipboard) {
    if (isPromise(text)) {
      return text.then((val) => fallbackCopy(validateString(val)))
    }
    return fallbackCopy(text)
  }
  if (isPromise(text)) {
    if (typeof ClipboardItem === "undefined") {
      return text.then((val) =>
        navigator.clipboard.writeText(validateString(val))
      )
    }
    return navigator.clipboard.write([
      new ClipboardItem({
        "text/plain": text.then(
          (val) => new Blob([validateString(val)], { type: "text/plain" })
        ),
      }),
    ])
  }
  return navigator.clipboard.writeText(text)
}

function validateString(val: unknown): string {
  if (typeof val !== "string" || val.length === 0) {
    throw new TypeError("Expected string, got " + typeof val)
  }
  if (val.length === 0) {
    throw new TypeError("Expected non-empty string")
  }
  return val
}

function fallbackCopy(text: string) {
  const el = document.createElement("textarea")
  el.value = text
  el.setAttribute("readonly", "")
  el.className = "absolute opacity-0 pointer-events-none"
  document.body.append(el)

  // Check if text is currently selected
  let selection = document.getSelection()
  const selected =
    selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : false

  el.select()
  document.execCommand("copy")
  el.remove()

  // Restore selection
  if (selected) {
    selection = document.getSelection()
    if (selection) {
      selection.removeAllRanges()
      selection.addRange(selected)
    }
  }

  return Promise.resolve()
}
