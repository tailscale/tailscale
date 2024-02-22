// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import * as Primitive from "@radix-ui/react-popover"
import cx from "classnames"
import React, { useCallback } from "react"
import ChevronDown from "src/assets/icons/chevron-down.svg?react"
import Copy from "src/assets/icons/copy.svg?react"
import NiceIP from "src/components/nice-ip"
import useToaster from "src/hooks/toaster"
import Button from "src/ui/button"
import { copyText } from "src/utils/clipboard"

/**
 * AddressCard renders a clickable IP address text that opens a
 * dialog with a copyable list of all addresses (IPv4, IPv6, DNS)
 * for the machine.
 */
export default function AddressCard({
  v4Address,
  v6Address,
  shortDomain,
  fullDomain,
  className,
  triggerClassName,
}: {
  v4Address: string
  v6Address: string
  shortDomain?: string
  fullDomain?: string
  className?: string
  triggerClassName?: string
}) {
  const children = (
    <ul className="flex flex-col divide-y rounded-md overflow-hidden">
      {shortDomain && <AddressRow label="short domain" value={shortDomain} />}
      {fullDomain && <AddressRow label="full domain" value={fullDomain} />}
      {v4Address && (
        <AddressRow
          key={v4Address}
          label="IPv4 address"
          ip={true}
          value={v4Address}
        />
      )}
      {v6Address && (
        <AddressRow
          key={v6Address}
          label="IPv6 address"
          ip={true}
          value={v6Address}
        />
      )}
    </ul>
  )

  return (
    <Primitive.Root>
      <Primitive.Trigger asChild>
        <Button
          variant="minimal"
          className={cx("-ml-1 px-1 py-0 font-normal", className)}
          suffixIcon={
            <ChevronDown className="w-5 h-5" stroke="#232222" /* gray-800 */ />
          }
          aria-label="See all addresses for this device."
        >
          <NiceIP className={triggerClassName} ip={v4Address ?? v6Address} />
        </Button>
      </Primitive.Trigger>
      <Primitive.Content
        className="shadow-popover origin-radix-popover state-open:animate-scale-in state-closed:animate-scale-out bg-white rounded-md z-50 max-w-sm"
        sideOffset={10}
        side="top"
      >
        {children}
      </Primitive.Content>
    </Primitive.Root>
  )
}

function AddressRow({
  label,
  value,
  ip,
}: {
  label: string
  value: string
  ip?: boolean
}) {
  const toaster = useToaster()
  const onCopyClick = useCallback(() => {
    copyText(value)
      .then(() => toaster.show({ message: `Copied ${label} to clipboard` }))
      .catch(() =>
        toaster.show({
          message: `Failed to copy ${label} to clipboard`,
          variant: "danger",
        })
      )
  }, [label, toaster, value])

  return (
    <li className="py flex items-center gap-2">
      <button
        className={cx(
          "relative flex group items-center transition-colors",
          "focus:outline-none focus-visible:ring",
          "disabled:text-text-muted enabled:hover:text-gray-500",
          "w-60 text-sm flex-1"
        )}
        onClick={onCopyClick}
        aria-label={`Copy ${value} to your clip board.`}
      >
        <div className="overflow-hidden pl-3 pr-10 py-2 tabular-nums">
          {ip ? (
            <NiceIP ip={value} />
          ) : (
            <div className="truncate m-w-full">{value}</div>
          )}
        </div>
        <span
          className={cx(
            "absolute right-0 pl-6 pr-3 bg-gradient-to-r from-transparent",
            "text-gray-900 group-hover:text-gray-600"
          )}
        >
          <Copy className="w-4 h-4" />
        </span>
      </button>
    </li>
  )
}
