import cx from "classnames"
import React, { useCallback, useEffect, useMemo, useState } from "react"
import { NodeData, NodeUpdate } from "src/hooks/node-data"
import { ReactComponent as Check } from "src/icons/check.svg"
import { ReactComponent as ChevronDown } from "src/icons/chevron-down.svg"
import { ReactComponent as Search } from "src/icons/search.svg"

const noExitNode = "None"
const runAsExitNode = "Run as exit node…"

export default function ExitNodeSelector({
  className,
  node,
  updateNode,
  disabled,
}: {
  className?: string
  node: NodeData
  updateNode: (update: NodeUpdate) => Promise<void> | undefined
  disabled?: boolean
}) {
  const [open, setOpen] = useState<boolean>(false)
  const [selected, setSelected] = useState(
    node.AdvertiseExitNode ? runAsExitNode : noExitNode
  )
  useEffect(() => {
    setSelected(node.AdvertiseExitNode ? runAsExitNode : noExitNode)
  }, [node])

  const handleSelect = useCallback(
    (item: string) => {
      setOpen(false)
      if (item === selected) {
        return // no update
      }
      const old = selected
      setSelected(item)
      var update: NodeUpdate = {}
      switch (item) {
        case noExitNode:
          // turn off exit node
          update = { AdvertiseExitNode: false }
          break
        case runAsExitNode:
          // turn on exit node
          update = { AdvertiseExitNode: true }
          break
      }
      updateNode(update)?.catch(() => setSelected(old))
    },
    [setOpen, selected, setSelected]
  )
  // TODO: close on click outside
  // TODO(sonia): allow choosing to use another exit node

  const [
    none, // not using exit nodes
    advertising, // advertising as exit node
    using, // using another exit node
  ] = useMemo(
    () => [
      selected === noExitNode,
      selected === runAsExitNode,
      selected !== noExitNode && selected !== runAsExitNode,
    ],
    [selected]
  )

  return (
    <>
      <div
        className={cx(
          "p-1.5 rounded-md border flex items-stretch gap-1.5",
          {
            "border-gray-200": none,
            "bg-amber-600 border-amber-600": advertising,
            "bg-indigo-500 border-indigo-500": using,
          },
          className
        )}
      >
        <button
          className={cx("flex-1 px-2 py-1.5 rounded-[1px]", {
            "bg-white hover:bg-stone-100": none,
            "bg-amber-600 hover:bg-orange-400": advertising,
            "bg-indigo-500 hover:bg-indigo-400": using,
            "cursor-not-allowed": disabled,
          })}
          onClick={() => setOpen(!open)}
          disabled={disabled}
        >
          <p
            className={cx(
              "text-neutral-500 text-xs text-left font-medium uppercase tracking-wide mb-1",
              { "bg-opacity-70 text-white": advertising || using }
            )}
          >
            Exit node
          </p>
          <div className="flex items-center">
            <p
              className={cx("text-neutral-800", {
                "text-white": advertising || using,
              })}
            >
              {selected === runAsExitNode ? "Running as exit node" : "None"}
            </p>
            <ChevronDown
              className={cx("ml-1", {
                "stroke-neutral-800": none,
                "stroke-white": advertising || using,
              })}
            />
          </div>
        </button>
        {(advertising || using) && (
          <button
            className={cx("px-3 py-2 rounded-sm text-white", {
              "bg-orange-400": advertising,
              "bg-indigo-400": using,
              "cursor-not-allowed": disabled,
            })}
            onClick={(e) => {
              e.preventDefault()
              e.stopPropagation()
              handleSelect(noExitNode)
            }}
            disabled={disabled}
          >
            Disable
          </button>
        )}
      </div>
      {open && (
        <div className="absolute ml-1.5 -mt-3 w-full max-w-md py-1 bg-white rounded-lg shadow">
          <div className="w-full px-4 py-2 flex items-center gap-2.5">
            <Search />
            <input
              className="flex-1 leading-snug"
              placeholder="Search exit nodes…"
            />
          </div>
          <DropdownSection
            items={[noExitNode, runAsExitNode]}
            selected={selected}
            onSelect={handleSelect}
          />
        </div>
      )}
    </>
  )
}

function DropdownSection({
  items,
  selected,
  onSelect,
}: {
  items: string[]
  selected?: string
  onSelect: (item: string) => void
}) {
  return (
    <div className="w-full mt-1 pt-1 border-t border-gray-200">
      {items.map((v) => (
        <button
          key={v}
          className="w-full px-4 py-2 flex justify-between items-center cursor-pointer hover:bg-stone-100"
          onClick={() => onSelect(v)}
        >
          <div className="leading-snug">{v}</div>
          {selected == v && <Check />}
        </button>
      ))}
    </div>
  )
}
