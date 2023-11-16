import cx from "classnames"
import React, { useCallback, useMemo, useState } from "react"
import { ReactComponent as Check } from "src/assets/icons/check.svg"
import { ReactComponent as ChevronDown } from "src/assets/icons/chevron-down.svg"
import useExitNodes, {
  ExitNode,
  noExitNode,
  runAsExitNode,
  trimDNSSuffix,
} from "src/hooks/exit-nodes"
import { NodeData, NodeUpdate, PrefsUpdate } from "src/hooks/node-data"
import Popover from "src/ui/popover"
import SearchInput from "src/ui/search-input"

export default function ExitNodeSelector({
  className,
  node,
  updateNode,
  updatePrefs,
  disabled,
}: {
  className?: string
  node: NodeData
  updateNode: (update: NodeUpdate) => Promise<void> | undefined
  updatePrefs: (p: PrefsUpdate) => Promise<void>
  disabled?: boolean
}) {
  const [open, setOpen] = useState<boolean>(false)
  const [selected, setSelected] = useState<ExitNode>(toSelectedExitNode(node))

  const handleSelect = useCallback(
    (n: ExitNode) => {
      setOpen(false)
      if (n.ID === selected.ID) {
        return // no update
      }

      const old = selected
      setSelected(n) // optimistic UI update
      const reset = () => setSelected(old)

      switch (n.ID) {
        case noExitNode.ID: {
          if (old === runAsExitNode) {
            // stop advertising as exit node
            updateNode({ AdvertiseExitNode: false })?.catch(reset)
          } else {
            // stop using exit node
            updatePrefs({ ExitNodeIDSet: true, ExitNodeID: "" }).catch(reset)
          }
          break
        }
        case runAsExitNode.ID: {
          const update = () =>
            updateNode({ AdvertiseExitNode: true })?.catch(reset)
          if (old !== noExitNode) {
            // stop using exit node first
            updatePrefs({ ExitNodeIDSet: true, ExitNodeID: "" })
              .catch(reset)
              .then(update)
          } else {
            update()
          }
          break
        }
        default: {
          const update = () =>
            updatePrefs({ ExitNodeIDSet: true, ExitNodeID: n.ID }).catch(reset)
          if (old === runAsExitNode) {
            // stop advertising as exit node first
            updateNode({ AdvertiseExitNode: false })?.catch(reset).then(update)
          } else {
            update()
          }
        }
      }
    },
    [setOpen, selected, setSelected]
  )

  const [
    none, // not using exit nodes
    advertising, // advertising as exit node
    using, // using another exit node
  ] = useMemo(
    () => [
      selected.ID === noExitNode.ID,
      selected.ID === runAsExitNode.ID,
      selected.ID !== noExitNode.ID && selected.ID !== runAsExitNode.ID,
    ],
    [selected]
  )

  return (
    <Popover
      open={disabled ? false : open}
      onOpenChange={setOpen}
      side="bottom"
      sideOffset={5}
      align="start"
      alignOffset={8}
      content={
        <ExitNodeSelectorInner
          node={node}
          selected={selected}
          onSelect={handleSelect}
        />
      }
      asChild
    >
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
              {selected.Location && (
                <>
                  <CountryFlag code={selected.Location.CountryCode} />{" "}
                </>
              )}
              {selected === runAsExitNode
                ? "Running as exit node"
                : selected.Name}
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
    </Popover>
  )
}

function toSelectedExitNode(data: NodeData): ExitNode {
  if (data.AdvertiseExitNode) {
    return runAsExitNode
  }
  if (data.ExitNodeStatus) {
    // TODO(sonia): also use online status
    const node = { ...data.ExitNodeStatus }
    if (node.Location) {
      // For mullvad nodes, use location as name.
      node.Name = `${node.Location.Country}: ${node.Location.City}`
    } else {
      // Otherwise use node name w/o DNS suffix.
      node.Name = trimDNSSuffix(node.Name, data.TailnetName)
    }
    return node
  }
  return noExitNode
}

function ExitNodeSelectorInner({
  node,
  selected,
  onSelect,
}: {
  node: NodeData
  selected: ExitNode
  onSelect: (node: ExitNode) => void
}) {
  const [filter, setFilter] = useState<string>("")
  const { data: exitNodes } = useExitNodes(node.TailnetName, filter)

  const hasNodes = useMemo(
    () => exitNodes.find((n) => n.nodes.length > 0),
    [exitNodes]
  )

  return (
    <div className="w-[calc(var(--radix-popover-trigger-width)-16px)] py-1 rounded-lg shadow">
      <SearchInput
        name="exit-node-search"
        inputClassName="w-full px-4 py-2"
        autoCorrect="off"
        autoComplete="off"
        autoCapitalize="off"
        placeholder="Search exit nodes…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
      />
      {/* TODO(sonia): use loading spinner when loading useExitNodes */}
      <div className="pt-1 border-t border-gray-200 max-h-64 overflow-y-scroll">
        {hasNodes ? (
          exitNodes.map(
            (group) =>
              group.nodes.length > 0 && (
                <div
                  key={group.id}
                  className="pb-1 mb-1 border-b last:border-b-0 last:mb-0"
                >
                  {group.name && (
                    <div className="px-4 py-2 text-neutral-500 text-xs font-medium uppercase tracking-wide">
                      {group.name}
                    </div>
                  )}
                  {group.nodes.map((n) => (
                    <ExitNodeSelectorItem
                      key={`${n.ID}-${n.Name}`}
                      node={n}
                      onSelect={() => onSelect(n)}
                      isSelected={selected.ID == n.ID}
                    />
                  ))}
                </div>
              )
          )
        ) : (
          <div className="text-center truncate text-gray-500 p-5">
            {filter
              ? `No exit nodes matching “${filter}”`
              : "No exit nodes available"}
          </div>
        )}
      </div>
    </div>
  )
}

function ExitNodeSelectorItem({
  node,
  isSelected,
  onSelect,
}: {
  node: ExitNode
  isSelected: boolean
  onSelect: () => void
}) {
  return (
    <button
      key={node.ID}
      className="w-full px-4 py-2 flex justify-between items-center cursor-pointer hover:bg-stone-100"
      onClick={onSelect}
    >
      <div>
        {node.Location && (
          <>
            <CountryFlag code={node.Location.CountryCode} />{" "}
          </>
        )}
        <span className="leading-snug">{node.Name}</span>
      </div>
      {isSelected && <Check />}
    </button>
  )
}

function CountryFlag({ code }: { code: string }) {
  return (
    countryFlags[code.toLowerCase()] || (
      <span className="font-medium text-gray-500 text-xs">
        {code.toUpperCase()}
      </span>
    )
  )
}

const countryFlags: { [countryCode: string]: string } = {
  ad: "🇦🇩",
  ae: "🇦🇪",
  af: "🇦🇫",
  ag: "🇦🇬",
  ai: "🇦🇮",
  al: "🇦🇱",
  am: "🇦🇲",
  ao: "🇦🇴",
  aq: "🇦🇶",
  ar: "🇦🇷",
  as: "🇦🇸",
  at: "🇦🇹",
  au: "🇦🇺",
  aw: "🇦🇼",
  ax: "🇦🇽",
  az: "🇦🇿",
  ba: "🇧🇦",
  bb: "🇧🇧",
  bd: "🇧🇩",
  be: "🇧🇪",
  bf: "🇧🇫",
  bg: "🇧🇬",
  bh: "🇧🇭",
  bi: "🇧🇮",
  bj: "🇧🇯",
  bl: "🇧🇱",
  bm: "🇧🇲",
  bn: "🇧🇳",
  bo: "🇧🇴",
  bq: "🇧🇶",
  br: "🇧🇷",
  bs: "🇧🇸",
  bt: "🇧🇹",
  bv: "🇧🇻",
  bw: "🇧🇼",
  by: "🇧🇾",
  bz: "🇧🇿",
  ca: "🇨🇦",
  cc: "🇨🇨",
  cd: "🇨🇩",
  cf: "🇨🇫",
  cg: "🇨🇬",
  ch: "🇨🇭",
  ci: "🇨🇮",
  ck: "🇨🇰",
  cl: "🇨🇱",
  cm: "🇨🇲",
  cn: "🇨🇳",
  co: "🇨🇴",
  cr: "🇨🇷",
  cu: "🇨🇺",
  cv: "🇨🇻",
  cw: "🇨🇼",
  cx: "🇨🇽",
  cy: "🇨🇾",
  cz: "🇨🇿",
  de: "🇩🇪",
  dj: "🇩🇯",
  dk: "🇩🇰",
  dm: "🇩🇲",
  do: "🇩🇴",
  dz: "🇩🇿",
  ec: "🇪🇨",
  ee: "🇪🇪",
  eg: "🇪🇬",
  eh: "🇪🇭",
  er: "🇪🇷",
  es: "🇪🇸",
  et: "🇪🇹",
  eu: "🇪🇺",
  fi: "🇫🇮",
  fj: "🇫🇯",
  fk: "🇫🇰",
  fm: "🇫🇲",
  fo: "🇫🇴",
  fr: "🇫🇷",
  ga: "🇬🇦",
  gb: "🇬🇧",
  gd: "🇬🇩",
  ge: "🇬🇪",
  gf: "🇬🇫",
  gg: "🇬🇬",
  gh: "🇬🇭",
  gi: "🇬🇮",
  gl: "🇬🇱",
  gm: "🇬🇲",
  gn: "🇬🇳",
  gp: "🇬🇵",
  gq: "🇬🇶",
  gr: "🇬🇷",
  gs: "🇬🇸",
  gt: "🇬🇹",
  gu: "🇬🇺",
  gw: "🇬🇼",
  gy: "🇬🇾",
  hk: "🇭🇰",
  hm: "🇭🇲",
  hn: "🇭🇳",
  hr: "🇭🇷",
  ht: "🇭🇹",
  hu: "🇭🇺",
  id: "🇮🇩",
  ie: "🇮🇪",
  il: "🇮🇱",
  im: "🇮🇲",
  in: "🇮🇳",
  io: "🇮🇴",
  iq: "🇮🇶",
  ir: "🇮🇷",
  is: "🇮🇸",
  it: "🇮🇹",
  je: "🇯🇪",
  jm: "🇯🇲",
  jo: "🇯🇴",
  jp: "🇯🇵",
  ke: "🇰🇪",
  kg: "🇰🇬",
  kh: "🇰🇭",
  ki: "🇰🇮",
  km: "🇰🇲",
  kn: "🇰🇳",
  kp: "🇰🇵",
  kr: "🇰🇷",
  kw: "🇰🇼",
  ky: "🇰🇾",
  kz: "🇰🇿",
  la: "🇱🇦",
  lb: "🇱🇧",
  lc: "🇱🇨",
  li: "🇱🇮",
  lk: "🇱🇰",
  lr: "🇱🇷",
  ls: "🇱🇸",
  lt: "🇱🇹",
  lu: "🇱🇺",
  lv: "🇱🇻",
  ly: "🇱🇾",
  ma: "🇲🇦",
  mc: "🇲🇨",
  md: "🇲🇩",
  me: "🇲🇪",
  mf: "🇲🇫",
  mg: "🇲🇬",
  mh: "🇲🇭",
  mk: "🇲🇰",
  ml: "🇲🇱",
  mm: "🇲🇲",
  mn: "🇲🇳",
  mo: "🇲🇴",
  mp: "🇲🇵",
  mq: "🇲🇶",
  mr: "🇲🇷",
  ms: "🇲🇸",
  mt: "🇲🇹",
  mu: "🇲🇺",
  mv: "🇲🇻",
  mw: "🇲🇼",
  mx: "🇲🇽",
  my: "🇲🇾",
  mz: "🇲🇿",
  na: "🇳🇦",
  nc: "🇳🇨",
  ne: "🇳🇪",
  nf: "🇳🇫",
  ng: "🇳🇬",
  ni: "🇳🇮",
  nl: "🇳🇱",
  no: "🇳🇴",
  np: "🇳🇵",
  nr: "🇳🇷",
  nu: "🇳🇺",
  nz: "🇳🇿",
  om: "🇴🇲",
  pa: "🇵🇦",
  pe: "🇵🇪",
  pf: "🇵🇫",
  pg: "🇵🇬",
  ph: "🇵🇭",
  pk: "🇵🇰",
  pl: "🇵🇱",
  pm: "🇵🇲",
  pn: "🇵🇳",
  pr: "🇵🇷",
  ps: "🇵🇸",
  pt: "🇵🇹",
  pw: "🇵🇼",
  py: "🇵🇾",
  qa: "🇶🇦",
  re: "🇷🇪",
  ro: "🇷🇴",
  rs: "🇷🇸",
  ru: "🇷🇺",
  rw: "🇷🇼",
  sa: "🇸🇦",
  sb: "🇸🇧",
  sc: "🇸🇨",
  sd: "🇸🇩",
  se: "🇸🇪",
  sg: "🇸🇬",
  sh: "🇸🇭",
  si: "🇸🇮",
  sj: "🇸🇯",
  sk: "🇸🇰",
  sl: "🇸🇱",
  sm: "🇸🇲",
  sn: "🇸🇳",
  so: "🇸🇴",
  sr: "🇸🇷",
  ss: "🇸🇸",
  st: "🇸🇹",
  sv: "🇸🇻",
  sx: "🇸🇽",
  sy: "🇸🇾",
  sz: "🇸🇿",
  tc: "🇹🇨",
  td: "🇹🇩",
  tf: "🇹🇫",
  tg: "🇹🇬",
  th: "🇹🇭",
  tj: "🇹🇯",
  tk: "🇹🇰",
  tl: "🇹🇱",
  tm: "🇹🇲",
  tn: "🇹🇳",
  to: "🇹🇴",
  tr: "🇹🇷",
  tt: "🇹🇹",
  tv: "🇹🇻",
  tw: "🇹🇼",
  tz: "🇹🇿",
  ua: "🇺🇦",
  ug: "🇺🇬",
  um: "🇺🇲",
  us: "🇺🇸",
  uy: "🇺🇾",
  uz: "🇺🇿",
  va: "🇻🇦",
  vc: "🇻🇨",
  ve: "🇻🇪",
  vg: "🇻🇬",
  vi: "🇻🇮",
  vn: "🇻🇳",
  vu: "🇻🇺",
  wf: "🇼🇫",
  ws: "🇼🇸",
  xk: "🇽🇰",
  ye: "🇾🇪",
  yt: "🇾🇹",
  za: "🇿🇦",
  zm: "🇿🇲",
  zw: "🇿🇼",
}
