// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { HTMLAttributes } from "react"

export type BadgeColor =
  | "blue"
  | "green"
  | "red"
  | "orange"
  | "yellow"
  | "gray"
  | "outline"

type Props = {
  variant: "tag" | "status"
  color: BadgeColor
} & HTMLAttributes<HTMLDivElement>

export default function Badge(props: Props) {
  const { className, color, variant, ...rest } = props

  return (
    <div
      className={cx(
        "inline-flex items-center align-middle justify-center font-medium",
        {
          "border border-gray-200 bg-gray-200 text-gray-600": color === "gray",
          "border border-green-50 bg-green-50 text-green-600":
            color === "green",
          "border border-blue-50 bg-blue-50 text-blue-600": color === "blue",
          "border border-orange-50 bg-orange-50 text-orange-600":
            color === "orange",
          "border border-yellow-50 bg-yellow-50 text-yellow-600":
            color === "yellow",
          "border border-red-50 bg-red-50 text-red-600": color === "red",
          "border border-gray-300 bg-white": color === "outline",
          "rounded-full px-2 py-1 leading-none": variant === "status",
          "rounded-sm px-1": variant === "tag",
        },
        className
      )}
      {...rest}
    />
  )
}

Badge.defaultProps = {
  color: "gray",
}
