// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { useCallback, useEffect, useMemo, useState } from "react"
import { useAPI } from "src/api"
import ChevronDown from "src/assets/icons/chevron-down.svg?react"
import Copy from "src/assets/icons/copy.svg?react"
import Globe from "src/assets/icons/globe.svg?react"
import Home from "src/assets/icons/home.svg?react"
import Plus from "src/assets/icons/plus.svg?react"
import { AuthResponse, canEdit } from "src/hooks/auth"
import useToaster from "src/hooks/toaster"
import {
  Destination,
  DestinationPort,
  DestinationProtocol,
  NodeData,
  ServeData,
  ShareType,
  Target,
  TargetType,
} from "src/types"
import Badge from "src/ui/badge"
import Button from "src/ui/button"
import Card from "src/ui/card"
import Collapsible from "src/ui/collapsible"
import DropdownMenu from "src/ui/dropdown-menu"
import EmptyState from "src/ui/empty-state"
import Input from "src/ui/input"
import QuickCopy from "src/ui/quick-copy"
import Tooltip from "src/ui/tooltip"
import { copyText } from "src/utils/clipboard"
import { assertNever, capitalize } from "src/utils/util"
import useSWR from "swr"

export default function ServeView({
  node,
  auth,
}: {
  node: NodeData
  auth: AuthResponse
}) {
  const api = useAPI()
  const { data, mutate } = useSWR<ServeData[]>("/serve/items")

  const hasItems = (data?.length || 0) > 0

  const [canEditServe, canEditFunnel] = useMemo(
    () => [
      canEdit("serve", auth) && node.Features.serve,
      canEdit("funnel", auth) && node.Features.funnel,
    ],
    [auth, node.Features]
  )
  const readonly = !canEditServe && !canEditFunnel // whole page is readonly

  const [editorOpen, setEditorOpen] = useState<boolean>(!hasItems)
  const [editingItem, setEditingItem] = useState<ServeData | undefined>()

  useEffect(() => setEditorOpen(!hasItems), [hasItems])

  return (
    <>
      <h1 className="mb-1">Share local content</h1>
      <p className="description mb-5">
        Share local ports, services, and content to your Tailscale network or to
        the broader internet.{" "}
        <a
          href="https://tailscale.com/kb/1312/serve"
          className="text-blue-700"
          target="_blank"
          rel="noreferrer"
        >
          Learn more &rarr;
        </a>
      </p>
      <div className="mt-5">
        {!readonly &&
          (editorOpen && !editingItem ? (
            <ServeEditorCard
              className="-mx-5"
              node={node}
              canEditServe={canEditServe}
              canEditFunnel={canEditFunnel}
              showCancelButton={hasItems}
              onClose={() => {
                mutate() // refresh from any edits
                setEditorOpen(false)
              }}
            />
          ) : (
            <Button
              intent="primary"
              prefixIcon={<Plus />}
              onClick={() => {
                setEditorOpen(true)
                setEditingItem(undefined)
              }}
            >
              Share more local content
            </Button>
          ))}
        {!data || data.length === 0 ? (
          <Card empty className="-mx-5 mt-10">
            <EmptyState description="Not sharing any content" />
          </Card>
        ) : (
          <div className="-mx-5 mt-10 flex flex-col gap-4">
            {data.map((d) => {
              const url = serveItemURL(d.destination, node)
              const isEditing =
                editingItem &&
                url === serveItemURL(editingItem.destination, node)
              return isEditing ? (
                <ServeEditorCard
                  key={url}
                  node={node}
                  canEditServe={canEditServe}
                  canEditFunnel={canEditFunnel}
                  initialState={editingItem}
                  showCancelButton
                  onClose={() => {
                    mutate() // refresh from any edits
                    setEditorOpen(false)
                    setEditingItem(undefined)
                  }}
                />
              ) : (
                <ServeItemCard
                  key={url}
                  url={url}
                  canEditServe={canEditServe}
                  canEditFunnel={canEditFunnel}
                  disabled={
                    readonly ||
                    (d.shareType === "serve" && !canEditServe) ||
                    (d.shareType === "funnel" && !canEditFunnel) ||
                    Boolean(d.isForeground)
                  }
                  data={d}
                  onEditSelect={() => {
                    setEditingItem(d)
                    setEditorOpen(true)
                  }}
                  onEditShareType={(t: ShareType) =>
                    api({
                      action: "patch-serve-item",
                      data: { ...d, shareType: t, isEdit: true },
                    }).then(() => mutate())
                  }
                />
              )
            })}
          </div>
        )}
      </div>
    </>
  )
}

function serveItemURL(destination: Destination, node: NodeData): string {
  let portPart = `:${destination.port}`
  if (destination.protocol === "https" && portPart === ":443") {
    portPart = ""
  } else if (destination.protocol === "http" && portPart === ":80") {
    portPart = ""
  }

  return `${
    destination.protocol === "tls-terminated-tcp" ? "tcp" : destination.protocol
  }://${node.DeviceName}.${node.TailnetName}${portPart}${destination.path}`
}

function ServeItemCard({
  data,
  url,
  canEditServe,
  canEditFunnel,
  disabled,
  onEditSelect,
  onEditShareType,
}: {
  data: ServeData
  url: string
  canEditServe: boolean
  canEditFunnel: boolean
  disabled: boolean
  onEditSelect: () => void
  onEditShareType: (t: ShareType) => void
}) {
  return (
    <Card noPadding className="p-4 w-full">
      <p className="text-gray-800 text-lg font-medium leading-[25.20px]">
        {data.target.type === "plainText"
          ? `Plain text “${data.target.value}”`
          : data.target.type === "localHttpPort"
          ? data.target.value
          : assertNever(data.target.type)}
      </p>
      {data.destination.protocol === "tls-terminated-tcp" && (
        <Badge className="mt-2 text-sm" variant="tag" color="green">
          TLS terminated
        </Badge>
      )}
      <p className="mt-2 text-gray-500 leading-snug">Shared at</p>
      <QuickCopy
        className="text-blue-700 font-medium"
        primaryActionValue={url}
        primaryActionSubject="url"
        hideAffordance
      >
        {url}
        <Copy className="inline ml-2 w-[18px] h-[18px] stroke-blue-700" />
      </QuickCopy>
      {/**
       * Dropdown to toggle share type is disabled if user is not allowed
       * to edit both serve and funnel.
       */}
      {!disabled && canEditServe && canEditFunnel && (
        <div className="mt-4 flex justify-between">
          <DropdownMenu
            asChild
            trigger={
              <Button
                className={cx({
                  "stroke-gray-400": disabled,
                  "stroke-gray-800": !disabled,
                })}
                sizeVariant="small"
                prefixIcon={
                  data.shareType === "serve" ? (
                    <Home className="w-[18px] h-[18px]" />
                  ) : data.shareType === "funnel" ? (
                    <Globe className="w-[18px] h-[18px]" />
                  ) : (
                    assertNever(data.shareType)
                  )
                }
                suffixIcon={<ChevronDown />}
                disabled={disabled}
              >
                {data.shareType === "serve"
                  ? "Shared within your tailnet"
                  : data.shareType === "funnel"
                  ? "Shared on the internet"
                  : assertNever(data.shareType)}
              </Button>
            }
            side="bottom"
            align="start"
          >
            <DropdownMenu.RadioGroup
              value={data.shareType}
              onValueChange={(t) => onEditShareType(t as ShareType)}
            >
              <DropdownMenu.RadioItem value="serve">
                Shared within your tailnet
              </DropdownMenu.RadioItem>
              <DropdownMenu.RadioItem value="funnel">
                Shared on the internet
              </DropdownMenu.RadioItem>
            </DropdownMenu.RadioGroup>
          </DropdownMenu>
          <Button sizeVariant="small" onClick={onEditSelect}>
            Edit
          </Button>
        </div>
      )}
      {data.isForeground && (
        <div className="mt-4 flex justify-end">
          <Tooltip
            content="This content cannot be edited because it’s shared in a
           foreground session started on the machine’s command line."
          >
            <Badge className="mt-2 text-sm" variant="tag">
              {/* TODO(ale): replace with different icon, this is placeholder */}
              <Globe className="stroke-gray-800 mr-[6px] h-3 w-3" />
              Foreground session
            </Badge>
          </Tooltip>
        </div>
      )}
    </Card>
  )
}

function ServeEditorCard({
  node,
  canEditServe,
  canEditFunnel,
  initialState,
  showCancelButton,
  onClose,
  className,
}: {
  node: NodeData
  canEditServe: boolean
  canEditFunnel: boolean
  initialState?: ServeData // editing existing config
  showCancelButton: boolean
  onClose: () => void
  className?: string
}) {
  const api = useAPI()
  const toaster = useToaster()
  const [error, setError] = useState<string | undefined>()

  const [data, setData] = useState<ServeData>(
    initialState || {
      target: { type: "localHttpPort", value: "" },
      destination: { protocol: "https", port: 443, path: "" },
      shareType: "serve",
    }
  )

  const onSubmit = useCallback(
    () =>
      api({
        action: "patch-serve-item",
        data: {
          ...data,
          isEdit: initialState !== undefined,
        },
      })
        .then(() => {
          copyText(serveItemURL(data.destination, node))
            .then(() => toaster.show({ message: "Copied url to clipboard" }))
            .catch(() =>
              toaster.show({
                message: "Failed to copy url",
                variant: "danger",
              })
            )
          onClose()
        })
        .catch((err) => setError(err?.message)),
    [api, data, initialState, node, onClose, toaster]
  )

  const onDelete = useCallback(
    (toDelete: ServeData) =>
      api({
        action: "delete-serve-item",
        data: toDelete,
      }).then(() => {
        toaster.show({ message: "Deleted item" })
        onClose()
      }),
    [api, onClose, toaster]
  )

  return (
    <Card noPadding className={cx("p-5 !border-0 shadow-popover", className)}>
      <TargetSection
        target={data.target}
        setTarget={(target) =>
          setData((o) => ({
            ...o,
            target,
            destination: {
              ...o.destination,
              protocol:
                /**
                 * "plainText" cannot be served over "tcp".
                 * So we reset the protocol to "https" when switching from
                 * "localHttpPort" to "plainText" incase "tcp" was selected.
                 */
                target.type === "plainText" ? "https" : o.destination.protocol,
            },
          }))
        }
      />
      <p className="mt-6 font-medium leading-snug">Share</p>
      <div className="mt-2.5 flex flex-col gap-2.5 stroke-green-800">
        <ShareRadioButton
          title="Within your tailnet"
          description="Everyone within your tailnet can access (Tailscale Serve)."
          icon={<Home />}
          selected={data.shareType === "serve"}
          onSelect={() => setData((o) => ({ ...o, shareType: "serve" }))}
          readonly={!canEditServe}
        />
        <ShareRadioButton
          title="On the internet"
          description="Anyone with the URL can access (Tailscale Funnel)."
          icon={<Globe />}
          selected={data.shareType === "funnel"}
          onSelect={() => setData((o) => ({ ...o, shareType: "funnel" }))}
          readonly={!canEditFunnel}
        />
      </div>
      <DestinationSection
        node={node}
        className="mt-6"
        target={data.target}
        destination={data.destination}
        setDestination={(destination) =>
          setData((o) => ({ ...o, destination }))
        }
      />
      <div className="mt-[30px] flex justify-between">
        <div>
          {/* TODO(ale): Style for error text. */}
          {error && (
            <p className="mb-2 text-sm leading-tight text-red-400">
              Could not share: {capitalize(error)}
            </p>
          )}
          <Button
            intent="primary"
            disabled={data.target.value === ""}
            onClick={onSubmit}
          >
            Share and copy URL
          </Button>
          {showCancelButton && (
            <Button intent="base" className="ml-3" onClick={onClose}>
              Cancel
            </Button>
          )}
        </div>
        {initialState && (
          <Button
            intent="danger"
            variant="minimal"
            disabled={data.target.value === ""}
            onClick={() => onDelete(initialState)}
          >
            Delete
          </Button>
        )}
      </div>
    </Card>
  )
}

function ShareRadioButton({
  title,
  description,
  icon,
  selected,
  onSelect,
  readonly,
}: {
  title: string
  description: string
  icon: React.ReactNode
  selected: boolean
  onSelect: () => void
  readonly: boolean
}) {
  return (
    <label className="flex mt-[10px]">
      <input
        type="radio"
        name={`${title}-radio`}
        className="radio mt-1"
        disabled={readonly}
        checked={selected}
        onChange={onSelect}
      />
      <div className="ml-3">
        <div className="flex items-center">
          {icon}
          <span className="ml-2 text-gray-800 leading-snug">{title}</span>
        </div>
        <div className="text-gray-500 text-sm leading-tight">{description}</div>
      </div>
    </label>
  )
}

function TargetSection({
  target,
  setTarget,
}: {
  target: Target
  setTarget: (next: Target) => void
}) {
  return (
    <>
      <p className="font-medium leading-snug">Target</p>
      <p className="mt-1 text-gray-500 text-sm leading-tight">
        The content you want to share.
      </p>
      <DropdownMenu
        asChild
        trigger={
          <Button className="mt-[10px]" sizeVariant="small">
            {target.type === "plainText"
              ? "Plain text"
              : target.type === "localHttpPort"
              ? "Local http port"
              : assertNever(target.type)}
            <ChevronDown className="inline ml-2 w-5 h-5 stroke-gray-800" />
          </Button>
        }
        side="bottom"
        align="start"
      >
        <DropdownMenu.RadioGroup
          value={target.type}
          onValueChange={(t) =>
            setTarget({
              type: t as TargetType,
              value: "", // clear out
            })
          }
        >
          <DropdownMenu.RadioItem value="plainText">
            Plain text
          </DropdownMenu.RadioItem>
          <DropdownMenu.RadioItem value="localHttpPort">
            Local http port
          </DropdownMenu.RadioItem>
        </DropdownMenu.RadioGroup>
      </DropdownMenu>
      <div className="mt-2 flex">
        {target.type === "localHttpPort" && (
          <div className="px-2 bg-gray-200 text-gray-500 rounded-l border border-r-0 border-gray-300 inline-flex items-center">
            http://localhost:
          </div>
        )}
        <Input
          className="flex-1"
          inputClassName={cx({
            "rounded-l-none": target.type === "localHttpPort",
          })}
          value={target.value}
          onChange={(e) => setTarget({ ...target, value: e.target.value })}
          placeholder={
            target.type === "plainText"
              ? "Hello world."
              : target.type === "localHttpPort"
              ? "8888"
              : assertNever(target.type)
          }
        />
      </div>
    </>
  )
}

function DestinationSection({
  node,
  target,
  destination,
  setDestination,
  className,
}: {
  node: NodeData
  target: Target
  destination: Destination
  setDestination: (next: Destination) => void
  className?: string
}) {
  const [urlPrefix, urlSuffix] = useMemo(() => {
    const fullURL = serveItemURL(destination, node)
    return fullURL.split(`://${node.DeviceName}`)
  }, [destination, node])

  return (
    <div className={className}>
      <Collapsible
        trigger="Destination options"
        triggerClassName="font-medium leading-snug !text-base text-gray-800 -ml-2"
      >
        <Card noPadding className="p-4 mt-4">
          <p className="text-gray-800 font-medium leading-snug">
            Destination protocol and port
          </p>
          <div className="mt-2 flex gap-2">
            <DropdownMenu
              asChild
              trigger={
                <Button sizeVariant="small">
                  {destination.protocol}
                  <ChevronDown className="inline ml-2 w-5 h-5 stroke-gray-800" />
                </Button>
              }
              side="bottom"
              align="start"
            >
              <DropdownMenu.RadioGroup
                value={destination.protocol}
                onValueChange={(p) =>
                  setDestination({
                    ...destination,
                    protocol: p as DestinationProtocol,
                  })
                }
              >
                <DropdownMenu.RadioItem value="https">
                  https
                </DropdownMenu.RadioItem>
                <DropdownMenu.RadioItem value="http">
                  http
                </DropdownMenu.RadioItem>
                {target.type !== "plainText" && (
                  <DropdownMenu.RadioItem value="tcp">
                    tcp
                  </DropdownMenu.RadioItem>
                )}
                {target.type !== "plainText" && (
                  <DropdownMenu.RadioItem value="tls-terminated-tcp">
                    tls-terminated-tcp
                  </DropdownMenu.RadioItem>
                )}
              </DropdownMenu.RadioGroup>
            </DropdownMenu>
            <DropdownMenu
              asChild
              trigger={
                <Button sizeVariant="small">
                  {destination.port}
                  <ChevronDown className="inline ml-2 w-5 h-5 stroke-gray-800" />
                </Button>
              }
              side="bottom"
              align="start"
            >
              {/**
               * TODO(ale's thoughts appreciated): port could be any value for serve,
               * only funnel is restricted to 443/8443/10000. We could make it an open
               * text input for serve if we want...
               * */}
              <DropdownMenu.RadioGroup
                value={`${destination.port}`}
                onValueChange={(p) =>
                  setDestination({
                    ...destination,
                    port: Number.parseInt(p) as DestinationPort,
                  })
                }
              >
                <DropdownMenu.RadioItem value="443">443</DropdownMenu.RadioItem>
                <DropdownMenu.RadioItem value="8443">
                  8443
                </DropdownMenu.RadioItem>
                <DropdownMenu.RadioItem value="10000">
                  10000
                </DropdownMenu.RadioItem>
              </DropdownMenu.RadioGroup>
            </DropdownMenu>
          </div>
          {(destination.protocol === "http" ||
            destination.protocol === "https") && (
            <>
              <p className="mt-4 text-gray-800 font-medium leading-snug">
                Destination path
              </p>
              <p className="text-gray-500 text-sm leading-tight">
                A slash-separated URL path appended to the destination url
              </p>
              <Input
                className="mt-2 w-full"
                value={destination.path}
                onChange={(e) =>
                  setDestination({ ...destination, path: e.target.value })
                }
                placeholder="/images/"
              />
            </>
          )}
        </Card>
      </Collapsible>
      <p className="mt-6 font-medium leading-snug">Preview destination URL</p>
      <p className="mt-3 text-gray-500 text-sm leading-tight">
        The URL where your content will be available.
      </p>
      <Card
        noPadding
        empty
        className="mt-2 p-2 text-sm font-medium tracking-wide" // TODO(ale): don't have SF-Mono font so used "tracking-wide"
      >
        <code className="text-gray-800">
          {urlPrefix}
          ://{node.DeviceName}
        </code>
        <code className="text-gray-400">{urlSuffix}</code>
      </Card>
    </div>
  )
}
