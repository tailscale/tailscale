import * as Primitive from "@radix-ui/react-collapsible"
import React, { useState } from "react"
import { ReactComponent as ChevronDown } from "src/assets/icons/chevron-down.svg"

type CollapsibleProps = {
  trigger?: string
  children: React.ReactNode
  open?: boolean
  onOpenChange?: (open: boolean) => void
}

export default function Collapsible(props: CollapsibleProps) {
  const { children, trigger, onOpenChange } = props
  const [open, setOpen] = useState(props.open)

  return (
    <Primitive.Root
      open={open}
      onOpenChange={(open) => {
        setOpen(open)
        onOpenChange?.(open)
      }}
    >
      <Primitive.Trigger className="inline-flex items-center text-gray-600 cursor-pointer hover:bg-stone-100 rounded text-sm font-medium pr-3 py-1 transition-colors">
        <span className="ml-2 mr-1.5 group-hover:text-gray-500 -rotate-90 state-open:rotate-0">
          <ChevronDown strokeWidth={3} className="stroke-gray-400 w-4" />
        </span>
        {trigger}
      </Primitive.Trigger>
      <Primitive.Content className="mt-2">{children}</Primitive.Content>
    </Primitive.Root>
  )
}
