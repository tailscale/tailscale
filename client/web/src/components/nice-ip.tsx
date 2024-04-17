// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React from "react"
import { isTailscaleIPv6 } from "src/utils/util"

type Props = {
  ip: string
  className?: string
}

/**
 * NiceIP displays IP addresses with nice truncation.
 */
export default function NiceIP(props: Props) {
  const { ip, className } = props

  if (!isTailscaleIPv6(ip)) {
    return <span className={className}>{ip}</span>
  }

  const [trimmable, untrimmable] = splitIPv6(ip)

  return (
    <span
      className={cx("inline-flex justify-start min-w-0 max-w-full", className)}
    >
      {trimmable.length > 0 && (
        <span className="truncate w-fit flex-shrink">{trimmable}</span>
      )}
      <span className="flex-grow-0 flex-shrink-0">{untrimmable}</span>
    </span>
  )
}

/**
 * Split an IPv6 address into two pieces, to help with truncating the middle.
 * Only exported for testing purposes. Do not use.
 */
export function splitIPv6(ip: string): [string, string] {
  // We want to split the IPv6 address into segments, but not remove the delimiter.
  // So we inject an invalid IPv6 character ("|") as a delimiter into the string,
  // then split on that.
  const parts = ip.replace(/(:{1,2})/g, "|$1").split("|")

  // Then we find the number of end parts that fits within the character limit,
  // and join them back together.
  const characterLimit = 12
  let characterCount = 0
  let idxFromEnd = 1
  for (let i = parts.length - 1; i >= 0; i--) {
    const part = parts[i]
    if (characterCount + part.length > characterLimit) {
      break
    }
    characterCount += part.length
    idxFromEnd++
  }

  const start = parts.slice(0, -idxFromEnd).join("")
  const end = parts.slice(-idxFromEnd).join("")

  return [start, end]
}
