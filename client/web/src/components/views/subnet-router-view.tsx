// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React, { useCallback, useMemo, useState } from "react"
import { ReactComponent as CheckCircle } from "src/assets/icons/check-circle.svg"
import { ReactComponent as Clock } from "src/assets/icons/clock.svg"
import { ReactComponent as Plus } from "src/assets/icons/plus.svg"
import * as Control from "src/components/control-components"
import { NodeData, NodeUpdaters } from "src/hooks/node-data"
import Button from "src/ui/button"
import Input from "src/ui/input"

export default function SubnetRouterView({
  readonly,
  node,
  nodeUpdaters,
}: {
  readonly: boolean
  node: NodeData
  nodeUpdaters: NodeUpdaters
}) {
  const [advertisedRoutes, hasRoutes, hasUnapprovedRoutes] = useMemo(() => {
    const routes = node.AdvertisedRoutes || []
    return [routes, routes.length > 0, routes.find((r) => !r.Approved)]
  }, [node.AdvertisedRoutes])

  const [inputOpen, setInputOpen] = useState<boolean>(
    advertisedRoutes.length === 0 && !readonly
  )
  const [inputText, setInputText] = useState<string>("")

  const resetInput = useCallback(() => {
    setInputText("")
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
          <div className="-mx-5 card shadow">
            <p className="font-medium leading-snug mb-3">
              Advertise new routes
            </p>
            <Input
              type="text"
              className="text-sm"
              placeholder="192.168.0.0/24"
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
            />
            <p className="my-2 h-6 text-gray-500 text-sm leading-tight">
              Add multiple routes by providing a comma-separated list.
            </p>
            <div className="flex gap-3">
              <Button
                intent="primary"
                onClick={() =>
                  nodeUpdaters
                    .postSubnetRoutes([
                      ...advertisedRoutes.map((r) => r.Route),
                      ...inputText.split(","),
                    ])
                    .then(resetInput)
                }
                disabled={!inputText}
              >
                Advertise {hasRoutes && "new "}routes
              </Button>
              {hasRoutes && <Button onClick={resetInput}>Cancel</Button>}
            </div>
          </div>
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
            <div className="px-5 py-3 bg-white rounded-lg border border-gray-200">
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
                      <Button
                        sizeVariant="small"
                        onClick={() =>
                          nodeUpdaters.postSubnetRoutes(
                            advertisedRoutes
                              .map((it) => it.Route)
                              .filter((it) => it !== r.Route)
                          )
                        }
                      >
                        Stop advertising…
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
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
          <div className="px-5 py-4 bg-gray-50 rounded-lg border border-gray-200 text-center text-gray-500">
            Not advertising any routes
          </div>
        )}
      </div>
    </>
  )
}
