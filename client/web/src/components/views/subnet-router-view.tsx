// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React, { useMemo, useState } from "react"
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
  const advertisedRoutes = useMemo(
    () => node.AdvertisedRoutes || [],
    [node.AdvertisedRoutes]
  )
  const [inputOpen, setInputOpen] = useState<boolean>(
    advertisedRoutes.length === 0 && !readonly
  )
  const [inputText, setInputText] = useState<string>("")

  return (
    <>
      <h1 className="mb-1">Subnet router</h1>
      <p className="description mb-5">
        Add devices to your tailnet without installing Tailscale.{" "}
        <a
          href="https://tailscale.com/kb/1019/subnets/"
          className="text-indigo-700"
          target="_blank"
          rel="noreferrer"
        >
          Learn more &rarr;
        </a>
      </p>
      {inputOpen ? (
        <div className="-mx-5 card shadow">
          <p className="font-medium leading-snug mb-3">Advertise new routes</p>
          <Input
            type="text"
            className="text-sm"
            placeholder="192.168.0.0/24"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
          />
          <p className="my-2 h-6 text-neutral-500 text-sm leading-tight">
            Add multiple routes by providing a comma-separated list.
          </p>
          <Button
            onClick={() =>
              nodeUpdaters
                .postSubnetRoutes([
                  ...advertisedRoutes.map((r) => r.Route),
                  ...inputText.split(","),
                ])
                .then(() => {
                  setInputText("")
                  setInputOpen(false)
                })
            }
            disabled={readonly || !inputText}
          >
            Advertise routes
          </Button>
        </div>
      ) : (
        <Button onClick={() => setInputOpen(true)} disabled={readonly}>
          <Plus />
          Advertise new route
        </Button>
      )}
      <div className="-mx-5 mt-10">
        {advertisedRoutes.length > 0 ? (
          <>
            <div className="px-5 py-3 bg-white rounded-lg border border-gray-200">
              {advertisedRoutes.map((r) => (
                <div
                  className="flex justify-between items-center pb-2.5 mb-2.5 border-b border-b-gray-200 last:pb-0 last:mb-0 last:border-b-0"
                  key={r.Route}
                >
                  <div className="text-neutral-800 leading-snug">{r.Route}</div>
                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1.5">
                      {r.Approved ? (
                        <CheckCircle className="w-4 h-4" />
                      ) : (
                        <Clock className="w-4 h-4" />
                      )}
                      {r.Approved ? (
                        <div className="text-emerald-800 text-sm leading-tight">
                          Approved
                        </div>
                      ) : (
                        <div className="text-neutral-500 text-sm leading-tight">
                          Pending approval
                        </div>
                      )}
                    </div>
                    <Button
                      intent="secondary"
                      className="text-sm font-medium"
                      onClick={() =>
                        nodeUpdaters.postSubnetRoutes(
                          advertisedRoutes
                            .map((it) => it.Route)
                            .filter((it) => it !== r.Route)
                        )
                      }
                      disabled={readonly}
                    >
                      Stop advertising…
                    </Button>
                  </div>
                </div>
              ))}
            </div>
            <Control.AdminContainer
              className="mt-3 w-full text-center text-neutral-500 text-sm leading-tight"
              node={node}
            >
              To approve routes, in the admin console go to{" "}
              <Control.AdminLink node={node} path={`/machines/${node.IP}`}>
                the machine’s route settings
              </Control.AdminLink>
              .
            </Control.AdminContainer>
          </>
        ) : (
          <div className="px-5 py-4 bg-stone-50 rounded-lg border border-gray-200 text-center text-neutral-500">
            Not advertising any routes
          </div>
        )}
      </div>
    </>
  )
}
