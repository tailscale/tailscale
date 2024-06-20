// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import * as MenuPrimitive from "@radix-ui/react-dropdown-menu"
import cx from "classnames"
import React from "react"
import Check from "src/assets/icons/check.svg?react"
import PortalContainerContext from "src/ui/portal-container-context"

type Props = {
  children: React.ReactNode
  asChild?: boolean
  trigger: React.ReactNode
  disabled?: boolean
} & Pick<
  MenuPrimitive.MenuContentProps,
  "side" | "sideOffset" | "align" | "alignOffset" | "onCloseAutoFocus"
> &
  Pick<MenuPrimitive.DropdownMenuProps, "open" | "onOpenChange">

/**
 * DropdownMenu is a floating menu with actions. It should be used to provide
 * additional actions for users that don't warrant a top-level button.
 */
export default function DropdownMenu(props: Props) {
  const {
    children,
    asChild,
    trigger,
    side,
    sideOffset,
    align,
    alignOffset,
    open,
    disabled,
    onOpenChange,
    onCloseAutoFocus,
  } = props

  return disabled ? (
    <>{trigger}</>
  ) : (
    <MenuPrimitive.Root open={open} onOpenChange={onOpenChange} dir="ltr">
      <MenuPrimitive.Trigger asChild={asChild}>{trigger}</MenuPrimitive.Trigger>
      <PortalContainerContext.Consumer>
        {(portalContainer) => (
          <MenuPrimitive.Portal container={portalContainer}>
            <MenuPrimitive.Content
              className="dropdown bg-white rounded-md py-1 z-50"
              side={side}
              sideOffset={sideOffset}
              align={align}
              alignOffset={alignOffset}
              collisionPadding={12}
              onCloseAutoFocus={onCloseAutoFocus}
            >
              {children}
            </MenuPrimitive.Content>
          </MenuPrimitive.Portal>
        )}
      </PortalContainerContext.Consumer>
    </MenuPrimitive.Root>
  )
}

DropdownMenu.defaultProps = {
  sideOffset: 10,
}

DropdownMenu.Group = DropdownMenuGroup
DropdownMenu.Item = DropdownMenuItem
DropdownMenu.RadioGroup = MenuPrimitive.RadioGroup
DropdownMenu.RadioItem = DropdownMenuRadioItem
/**
 * DropdownMenu.Separator should be used to divide items into sections within a
 * DropdownMenu.
 */
DropdownMenu.Separator = DropdownSeparator

export const dropdownMenuItemClasses = "block px-4 py-2"
export const dropdownMenuItemInteractiveClasses =
  "cursor-pointer hover:enabled:bg-bg-menu-item-hover focus:outline-none focus:bg-bg-menu-item-hover"

type CommonMenuItemProps = {
  className?: string
  disabled?: boolean
  /**
   * hidden determines whether or not the menu item should appear. It's exposed as
   * a convenience for menus with many nested conditionals.
   */
  hidden?: boolean
}

type DropdownMenuGroupProps = CommonMenuItemProps & MenuPrimitive.MenuGroupProps

function DropdownMenuGroup(props: DropdownMenuGroupProps) {
  const { className, ...rest } = props

  return (
    <MenuPrimitive.Group
      className={cx(className, dropdownMenuItemClasses)}
      {...rest}
    />
  )
}

type DropdownMenuItemProps = {
  intent?: "danger"
  stopPropagation?: boolean
} & CommonMenuItemProps &
  Omit<MenuPrimitive.MenuItemProps, "onClick">

function DropdownMenuItem(props: DropdownMenuItemProps) {
  const { className, disabled, intent, stopPropagation, hidden, ...rest } =
    props

  if (hidden === true) {
    return null
  }

  return (
    <MenuPrimitive.Item
      className={cx(
        className,
        dropdownMenuItemClasses,
        dropdownMenuItemInteractiveClasses,
        {
          "text-red-400": intent === "danger",
          "text-gray-400 bg-white cursor-default": disabled,
        }
      )}
      disabled={disabled}
      onClick={stopPropagation ? (e) => e.stopPropagation() : undefined}
      {...rest}
    />
  )
}

type DropdownMenuRadioItemProps = CommonMenuItemProps &
  MenuPrimitive.MenuRadioItemProps

function DropdownMenuRadioItem(props: DropdownMenuRadioItemProps) {
  const { className, disabled, hidden, children, ...rest } = props

  if (hidden === true) {
    return null
  }

  return (
    <MenuPrimitive.RadioItem
      className={cx(
        className,
        dropdownMenuItemClasses,
        dropdownMenuItemInteractiveClasses,
        "pl-9 relative flex items-center",
        {
          "text-gray-400 bg-white cursor-default": disabled,
        }
      )}
      disabled={disabled}
      {...rest}
    >
      <MenuPrimitive.ItemIndicator>
        <Check className="relative -ml-6" width="1em" height="1em" />
      </MenuPrimitive.ItemIndicator>
      {children}
    </MenuPrimitive.RadioItem>
  )
}

type DropdownSeparatorProps = Omit<CommonMenuItemProps, "disabled"> &
  MenuPrimitive.MenuSeparatorProps

function DropdownSeparator(props: DropdownSeparatorProps) {
  const { className, hidden, ...rest } = props

  if (hidden === true) {
    return null
  }

  return (
    <MenuPrimitive.Separator
      className={cx("my-1 border-b", className)}
      {...rest}
    />
  )
}
