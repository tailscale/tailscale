// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { HTMLProps } from "react"
import LoadingDots from "src/ui/loading-dots"

type Props = {
  type?: "button" | "submit" | "reset"
  sizeVariant?: "input" | "small" | "medium" | "large"
  /**
   * variant is the visual style of the button. By default, this is a filled
   * button. For a less prominent button, use minimal.
   */
  variant?: Variant
  /**
   * intent describes the semantic meaning of the button's action. For
   * dangerous or destructive actions, use danger. For actions that should
   * be the primary focus, use primary.
   */
  intent?: Intent

  active?: boolean
  /**
   * prefixIcon is an icon or piece of content shown at the start of a button.
   */
  prefixIcon?: React.ReactNode
  /**
   * suffixIcon is an icon or piece of content shown at the end of a button.
   */
  suffixIcon?: React.ReactNode
  /**
   * loading displays a loading indicator inside the button when set to true.
   * The sizing of the button is not affected by this prop.
   */
  loading?: boolean
  /**
   * iconOnly indicates that the button contains only an icon. This is used to
   * adjust styles to be appropriate for an icon-only button.
   */
  iconOnly?: boolean
  /**
   * textAlign align the text center or left. If left aligned, any icons will
   * move to the sides of the button.
   */
  textAlign?: "center" | "left"
} & HTMLProps<HTMLButtonElement>

export type Variant = "filled" | "minimal"
export type Intent = "base" | "primary" | "warning" | "danger" | "black"

const Button = React.forwardRef<HTMLButtonElement, Props>((props, ref) => {
  const {
    className,
    variant = "filled",
    intent = "base",
    sizeVariant = "large",
    disabled,
    children,
    loading,
    active,
    iconOnly,
    prefixIcon,
    suffixIcon,
    textAlign,
    ...rest
  } = props

  const hasIcon = Boolean(prefixIcon || suffixIcon)

  return (
    <button
      className={cx(
        "button",
        {
          // base filled
          "bg-gray-0 border-gray-300 enabled:hover:bg-gray-100 enabled:hover:border-gray-300 enabled:hover:text-gray-900 disabled:border-gray-200 disabled:text-gray-400":
            intent === "base" && variant === "filled",
          "enabled:bg-gray-200 enabled:border-gray-300":
            intent === "base" && variant === "filled" && active,
          // primary filled
          "bg-blue-500 border-blue-500 text-white enabled:hover:bg-blue-600 enabled:hover:border-blue-600 disabled:text-blue-50 disabled:bg-blue-300 disabled:border-blue-300":
            intent === "primary" && variant === "filled",
          // danger filled
          "bg-red-400 border-red-400 text-white enabled:hover:bg-red-500 enabled:hover:border-red-500 disabled:text-red-50 disabled:bg-red-300 disabled:border-red-300":
            intent === "danger" && variant === "filled",
          // warning filled
          "bg-yellow-300 border-yellow-300 text-white enabled:hover:bg-yellow-400 enabled:hover:border-yellow-400 disabled:text-yellow-50 disabled:bg-yellow-200 disabled:border-yellow-200":
            intent === "warning" && variant === "filled",
          // black filled
          "bg-gray-800 border-gray-800 text-white enabled:hover:bg-gray-900 enabled:hover:border-gray-900 disabled:opacity-75":
            intent === "black" && variant === "filled",

          // minimal button (base variant, black is also included because its not supported for minimal buttons)
          "bg-transparent border-transparent shadow-none disabled:border-transparent disabled:text-gray-400":
            variant === "minimal",
          "text-gray-700 enabled:focus-visible:bg-gray-100 enabled:hover:bg-gray-100 enabled:hover:text-gray-800":
            variant === "minimal" && (intent === "base" || intent === "black"),
          "enabled:bg-gray-200 border-gray-300":
            variant === "minimal" &&
            (intent === "base" || intent === "black") &&
            active,
          // primary minimal
          "text-blue-600 enabled:focus-visible:bg-blue-0 enabled:hover:bg-blue-0 enabled:hover:text-blue-800":
            variant === "minimal" && intent === "primary",
          // danger minimal
          "text-red-600 enabled:focus-visible:bg-red-0 enabled:hover:bg-red-0 enabled:hover:text-red-800":
            variant === "minimal" && intent === "danger",
          // warning minimal
          "text-yellow-600 enabled:focus-visible:bg-orange-0 enabled:hover:bg-orange-0 enabled:hover:text-orange-800":
            variant === "minimal" && intent === "warning",

          // sizeVariants
          "px-3 py-[0.35rem]": sizeVariant === "medium",
          "h-input": sizeVariant === "input",
          "px-3 text-sm py-[0.35rem]": sizeVariant === "small",
          "button-active relative z-10": active === true,
          "px-3":
            iconOnly && (sizeVariant === "large" || sizeVariant === "input"),
          "px-2":
            iconOnly && (sizeVariant === "medium" || sizeVariant === "small"),
          "icon-parent gap-2": hasIcon,
        },
        className
      )}
      ref={ref}
      disabled={disabled || loading}
      {...rest}
    >
      {prefixIcon && <span className="flex-shrink-0">{prefixIcon}</span>}
      {loading && (
        <LoadingDots className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 text-current" />
      )}
      {children && (
        <span
          className={cx({
            "text-transparent": loading === true,
            "text-left flex-1": textAlign === "left",
          })}
        >
          {children}
        </span>
      )}
      {suffixIcon && <span className="flex-shrink-0">{suffixIcon}</span>}
    </button>
  )
})

export default Button
