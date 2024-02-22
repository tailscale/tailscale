// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { useCallback, useMemo, useState } from "react"
import { useAPI } from "src/api"
import CheckCircle from "src/assets/icons/check-circle.svg?react"
import Clock from "src/assets/icons/clock.svg?react"
import Plus from "src/assets/icons/plus.svg?react"
import * as Control from "src/components/control-components"
import { NodeData } from "src/types"
import Button from "src/ui/button"
import Card from "src/ui/card"
import Dialog from "src/ui/dialog"
import EmptyState from "src/ui/empty-state"
import Input from "src/ui/input"

export default function SubnetRouterView({
  readonly,
  node,
}: {
  readonly: boolean
  node: NodeData
}) {
  const api = useAPI()

  const [advertisedRoutes, hasRoutes, hasUnapprovedRoutes] = useMemo(() => {
    const routes = node.AdvertisedRoutes || []
    return [routes, routes.length > 0, routes.find((r) => !r.Approved)]
  }, [node.AdvertisedRoutes])

  const [inputOpen, setInputOpen] = useState<boolean>(
    advertisedRoutes.length === 0 && !readonly
  )
  const [inputText, setInputText] = useState<string>("")
  const [postError, setPostError] = useState<string>()

  const resetInput = useCallback(() => {
    setInputText("")
    setPostError("")
    setInputOpen(false)
  }, [])

  return (
    <>
      <h1 className="mb-1">Subnet router</h1>
      <p className="description mb-5">
        Add devices to your tailnet without installing Tailscale.{" "}
        <a
          href="https://tailscale.com/kb/1019/subnets/"
          className="text-blue-700"
          target="_blank"
          rel="noreferrer"
        >
          Learn more &rarr;
        </a>
      </p>
      {!readonly &&
        (inputOpen ? (
          <Card noPadding className="-mx-5 p-5 !border-0 shadow-popover">
            <p className="font-medium leading-snug mb-3">
              Advertise new routes
            </p>
            <Input
              type="text"
              className="text-sm"
              placeholder="192.168.0.0/24"
              value={inputText}
              onChange={(e) => {
                setPostError("")
                setInputText(e.target.value)
              }}
            />
            <p
              className={cx("my-2 h-6 text-sm leading-tight", {
                "text-gray-500": !postError,
                "text-red-400": postError,
              })}
            >
              {postError ||
                "Add multiple routes by providing a comma-separated list."}
            </p>
            <div className="flex gap-3">
              <Button
                intent="primary"
                onClick={() =>
                  api({
                    action: "update-routes",
                    data: [
                      ...advertisedRoutes,
                      ...inputText
                        .split(",")
                        .map((r) => ({ Route: r, Approved: false })),
                    ],
                  })
                    .then(resetInput)
                    .catch((err: Error) => setPostError(err.message))
                }
                disabled={!inputText || postError !== ""}
              >
                Advertise {hasRoutes && "new "}routes
              </Button>
              {hasRoutes && <Button onClick={resetInput}>Cancel</Button>}
            </div>
          </Card>
        ) : (
          <Button
            intent="primary"
            prefixIcon={<Plus />}
            onClick={() => setInputOpen(true)}
          >
            Advertise new routes
          </Button>
        ))}
      <div className="-mx-5 mt-10">
        {hasRoutes ? (
          <>
            <Card noPadding className="px-5 py-3">
              {advertisedRoutes.map((r) => (
                <div
                  className="flex justify-between items-center pb-2.5 mb-2.5 border-b border-b-gray-200 last:pb-0 last:mb-0 last:border-b-0"
                  key={r.Route}
                >
                  <div className="text-gray-800 leading-snug">{r.Route}</div>
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1.5">
                      {r.Approved ? (
                        <CheckCircle className="w-4 h-4" />
                      ) : (
                        <Clock className="w-4 h-4" />
                      )}
                      {r.Approved ? (
                        <div className="text-green-500 text-sm leading-tight">
                          Approved
                        </div>
                      ) : (
                        <div className="text-gray-500 text-sm leading-tight">
                          Pending approval
                        </div>
                      )}
                    </div>
                    {!readonly && (
                      <StopAdvertisingDialog
                        onSubmit={() =>
                          api({
                            action: "update-routes",
                            data: advertisedRoutes.filter(
                              (it) => it.Route !== r.Route
                            ),
                          })
                        }
                      />
                    )}
                  </div>
                </div>
              ))}
            </Card>
            {hasUnapprovedRoutes && (
              <Control.AdminContainer
                className="mt-3 w-full text-center text-gray-500 text-sm leading-tight"
                node={node}
              >
                To approve routes, in the admin console go to{" "}
                <Control.AdminLink node={node} path={`/machines/${node.IPv4}`}>
                  the machine’s route settings
                </Control.AdminLink>
                .
              </Control.AdminContainer>
            )}
          </>
        ) : (
          <Card empty>
            <EmptyState description="Not advertising any routes" />
          </Card>
        )}
      </div>
    </>
  )
}

function StopAdvertisingDialog({ onSubmit }: { onSubmit: () => void }) {
  return (
    <Dialog
      className="max-w-md"
      title="Stop advertising route"
      trigger={<Button sizeVariant="small">Stop advertising…</Button>}
    >
      <Dialog.Form
        cancelButton
        submitButton="Stop advertising"
        destructive
        onSubmit={onSubmit}
      >
        Any active connections between devices over this route will be broken.
      </Dialog.Form>
    </Dialog>
  )
}
