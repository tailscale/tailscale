import * as PopoverPrimitive from "@radix-ui/react-popover"
import cx from "classnames"
import React, { ReactNode } from "react"

type Props = {
  className?: string
  content: ReactNode
  children: ReactNode

  /**
   * asChild renders the trigger element without wrapping it in a button. Use
   * this when you want to use a `button` element as the trigger.
   */
  asChild?: boolean
  /**
   * side is the side of the direction from the target element to render the
   * popover.
   */
  side?: "top" | "bottom" | "left" | "right"
  /**
   * sideOffset is how far from a give side to render the popover.
   */
  sideOffset?: number
  /**
   * align is how to align the popover with the target element.
   */
  align?: "start" | "center" | "end"
  /**
   * alignOffset is how far off of the alignment point to render the popover.
   */
  alignOffset?: number

  open?: boolean
  onOpenChange?: (open: boolean) => void
}

/**
 * Popover is a UI component that allows rendering unique controls in a floating
 * popover, attached to a trigger element. It appears on click and manages focus
 * on its own behalf.
 *
 * To use the Popover, pass the content as children, and give it a `trigger`:
 *
 *    <Popover trigger={<span>Open popover</span>}>
 *      <p>Hello world!</p>
 *    </Popover>
 *
 * By default, the toggle is wrapped in an accessible <button> tag. You can
 * customize by providing your own button and using the `asChild` prop.
 *
 *    <Popover trigger={<Button>Hello</Button>} asChild>
 *      <p>Hello world!</p>
 *    </Popover>
 *
 * The former style is recommended whenever possible.
 */
export default function Popover(props: Props) {
  const {
    children,
    className,
    content,
    side,
    sideOffset,
    align,
    alignOffset,
    asChild,
    open,
    onOpenChange,
  } = props

  return (
    <PopoverPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <PopoverPrimitive.Trigger asChild={asChild}>
        {children}
      </PopoverPrimitive.Trigger>
      <PortalContainerContext.Consumer>
        {(portalContainer) => (
          <PopoverPrimitive.Portal container={portalContainer}>
            <PopoverPrimitive.Content
              className={cx(
                "origin-radix-popover shadow-popover bg-white rounded-md z-50",
                "state-open:animate-scale-in state-closed:animate-scale-out",
                className
              )}
              side={side}
              sideOffset={sideOffset}
              align={align}
              alignOffset={alignOffset}
              collisionPadding={12}
            >
              {content}
            </PopoverPrimitive.Content>
          </PopoverPrimitive.Portal>
        )}
      </PortalContainerContext.Consumer>
    </PopoverPrimitive.Root>
  )
}

Popover.defaultProps = {
  sideOffset: 10,
}

const PortalContainerContext = React.createContext<HTMLElement | undefined>(
  undefined
)
