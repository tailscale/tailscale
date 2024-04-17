// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { useEffect, useRef, useState } from "react"
import useToaster from "src/hooks/toaster"
import { copyText } from "src/utils/clipboard"

type Props = {
  className?: string
  hideAffordance?: boolean
  /**
   * primaryActionSubject is the subject of the toast confirmation message
   * "Copied <subject> to clipboard"
   */
  primaryActionSubject: string
  primaryActionValue: string
  secondaryActionName?: string
  secondaryActionValue?: string
  /**
   * secondaryActionSubject is the subject of the toast confirmation message
   * prompted by the secondary action "Copied <subject> to clipboard"
   */
  secondaryActionSubject?: string
  children?: React.ReactNode

  /**
   * onSecondaryAction is used to trigger events when the secondary copy
   * function is used. It is not used when the secondary action is hidden.
   */
  onSecondaryAction?: () => void
}

/**
 * QuickCopy is a UI component that allows for copying textual content in one click.
 */
export default function QuickCopy(props: Props) {
  const {
    className,
    hideAffordance,
    primaryActionSubject,
    primaryActionValue,
    secondaryActionValue,
    secondaryActionName,
    secondaryActionSubject,
    onSecondaryAction,
    children,
  } = props
  const toaster = useToaster()
  const containerRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLDivElement>(null)
  const [showButton, setShowButton] = useState(false)

  useEffect(() => {
    if (!showButton) {
      return
    }
    if (!containerRef.current || !buttonRef.current) {
      return
    }
    // We don't need to watch any `resize` event because it's pretty unlikely
    // the browser will resize while their cursor is over one of these items.
    const rect = containerRef.current.getBoundingClientRect()
    const maximumPossibleWidth = window.innerWidth - rect.left + 4

    // We add the border-width (1px * 2 sides) and the padding (0.5rem * 2 sides)
    // and add 1px for rounding up the calculation in order to get the final
    // maxWidth value. This should be kept in sync with the CSS classes below.
    buttonRef.current.style.maxWidth = `${maximumPossibleWidth}px`
    buttonRef.current.style.visibility = "visible"
  }, [showButton])

  const handlePrimaryAction = () => {
    copyText(primaryActionValue)
    toaster.show({
      message: `Copied ${primaryActionSubject} to the clipboard`,
    })
  }

  const handleSecondaryAction = () => {
    if (!secondaryActionValue) {
      return
    }
    copyText(secondaryActionValue)
    toaster.show({
      message: `Copied ${
        secondaryActionSubject || secondaryActionName
      } to the clipboard`,
    })
    onSecondaryAction?.()
  }

  return (
    <div
      className="flex relative min-w-0"
      ref={containerRef}
      // Since the affordance is a child of this element, we assign both event
      // handlers here.
      onMouseLeave={() => setShowButton(false)}
    >
      <div
        onMouseEnter={() => setShowButton(true)}
        className={cx("truncate", className)}
      >
        {children}
      </div>
      {!hideAffordance && (
        <button
          onMouseEnter={() => setShowButton(true)}
          onClick={handlePrimaryAction}
          className={cx("cursor-pointer text-blue-500", { "ml-2": children })}
        >
          Copy
        </button>
      )}

      {showButton && (
        <div
          className="absolute -mt-1 -ml-2 -top-px -left-px
          shadow-md cursor-pointer rounded-md active:shadow-sm
          transition-shadow duration-100 ease-in-out z-50"
          style={{ visibility: "hidden" }}
          ref={buttonRef}
        >
          <div className="flex border rounded-md button-outline bg-white">
            <div
              className={cx("flex min-w-0 py-1 px-2 hover:bg-gray-0", {
                "rounded-md": !secondaryActionValue,
                "rounded-l-md": secondaryActionValue,
              })}
              onClick={handlePrimaryAction}
            >
              <span
                className={cx(className, "inline-block select-none truncate")}
              >
                {children}
              </span>
              <button
                className={cx("cursor-pointer text-blue-500", {
                  "ml-2": children,
                })}
              >
                Copy
              </button>
            </div>

            {secondaryActionValue && (
              <div
                className="text-blue-500 py-1 px-2 border-l hover:bg-gray-100 rounded-r-md"
                onClick={handleSecondaryAction}
              >
                {secondaryActionName}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
