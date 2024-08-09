// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import * as TooltipPrimitive from "@radix-ui/react-tooltip"
import React from "react"
import PortalContainerContext from "src/ui/portal-container-context"

type Props = {
  side?: "top" | "right" | "bottom" | "left"
  align?: "start" | "center" | "end"
  delay?: number
  content: React.ReactNode
  children: React.ReactNode
  asChild?: boolean // when true, renders the tooltip trigger as a child; defaults to true
}

export default function Tooltip(props: Props) {
  const { delay = 150, side, align, content, children, asChild = true } = props

  return (
    <TooltipPrimitive.Root delayDuration={delay}>
      <TooltipPrimitive.TooltipTrigger asChild={asChild}>
        {asChild ? <span>{children}</span> : children}
      </TooltipPrimitive.TooltipTrigger>
      {content && (
        <PortalContainerContext.Consumer>
          {(portalContainer) => (
            <TooltipPrimitive.Portal container={portalContainer}>
              <TooltipPrimitive.Content
                className="tooltip"
                role="tooltip"
                sideOffset={10}
                side={side}
                align={align}
                aria-live="polite"
                collisionPadding={12}
              >
                {content}
              </TooltipPrimitive.Content>
            </TooltipPrimitive.Portal>
          )}
        </PortalContainerContext.Consumer>
      )}
    </TooltipPrimitive.Root>
  )
}

Tooltip.Provider = TooltipPrimitive.Provider
