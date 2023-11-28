// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { ButtonHTMLAttributes } from "react"

type Props = {
  intent?: "primary" | "secondary"
} & ButtonHTMLAttributes<HTMLButtonElement>

export default function Button(props: Props) {
  const { intent = "primary", className, disabled, children, ...rest } = props

  return (
    <button
      className={cx(
        "px-3 py-2 rounded shadow justify-center items-center gap-2.5 inline-flex font-medium",
        {
          "bg-indigo-500 text-white": intent === "primary" && !disabled,
          "bg-indigo-400 text-indigo-200": intent === "primary" && disabled,
          "bg-stone-50 shadow border border-stone-200 text-neutral-800":
            intent === "secondary",
          "cursor-not-allowed": disabled,
        },
        className
      )}
      {...rest}
      disabled={disabled}
    >
      {children}
    </button>
  )
}
