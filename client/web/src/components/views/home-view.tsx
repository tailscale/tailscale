// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { useMemo } from "react"
import { apiFetch } from "src/api"
import ArrowRight from "src/assets/icons/arrow-right.svg?react"
import Machine from "src/assets/icons/machine.svg?react"
import AddressCard from "src/components/address-copy-card"
import ExitNodeSelector from "src/components/exit-node-selector"
import { AuthResponse, canEdit } from "src/hooks/auth"
import { useI18n } from "src/i18n"
import { NodeData } from "src/types"
import Card from "src/ui/card"
import { Link, useLocation } from "wouter"

export default function HomeView({
  node,
  auth,
}: {
  node: NodeData
  auth: AuthResponse
}) {
  const { plural, t } = useI18n()
  const [allSubnetRoutes, pendingSubnetRoutes] = useMemo(
    () => [
      node.AdvertisedRoutes?.length,
      node.AdvertisedRoutes?.filter((r) => !r.Approved).length,
    ],
    [node.AdvertisedRoutes]
  )

  return (
    <div className="mb-12 w-full">
      <h2 className="mb-3">{t("home.thisDevice")}</h2>
      <Card noPadding className="-mx-5 p-5 mb-9">
        <div className="flex justify-between items-center text-lg mb-5">
          <Link className="flex items-center" to="/details">
            <div className="w-10 h-10 bg-gray-100 rounded-full justify-center items-center inline-flex">
              <Machine />
            </div>
            <div className="ml-3">
              <div className="text-gray-800 text-lg font-medium leading-snug">
                {node.DeviceName}
              </div>
              <p className="text-gray-500 text-sm leading-[18.20px] flex items-center gap-2">
                <span
                  className={cx("w-2 h-2 inline-block rounded-full", {
                    "bg-green-300": node.Status === "Running",
                    "bg-gray-300": node.Status !== "Running",
                  })}
                />
                {node.Status === "Running"
                  ? t("home.connected")
                  : t("home.offline")}
              </p>
            </div>
          </Link>
          <AddressCard
            className="-mr-2"
            triggerClassName="relative text-gray-800 text-lg leading-[25.20px]"
            v4Address={node.IPv4}
            v6Address={node.IPv6}
            shortDomain={node.DeviceName}
            fullDomain={`${node.DeviceName}.${node.TailnetName}`}
          />
        </div>
        {(node.Features["advertise-exit-node"] ||
          node.Features["use-exit-node"]) && (
          <ExitNodeSelector
            className="mb-5"
            node={node}
            disabled={!canEdit("exitnodes", auth)}
          />
        )}
        <Link
          className="link font-medium"
          to="/details"
          onClick={() => apiFetch("/device-details-click", "POST")}
        >
          {t("home.deviceDetails")} &rarr;
        </Link>
      </Card>
      <h2 className="mb-3">{t("home.settings")}</h2>
      <div className="grid gap-3">
        {node.Features["advertise-routes"] && (
          <SettingsCard
            link="/subnets"
            title={t("home.subnetRouter")}
            body={t("home.subnetDescription")}
            badge={
              allSubnetRoutes
                ? {
                    text: `${allSubnetRoutes} ${plural(allSubnetRoutes, "home.route", "home.routes")}`,
                  }
                : undefined
            }
            footer={
              pendingSubnetRoutes
                ? t("home.pendingApproval", {
                    count: pendingSubnetRoutes,
                    route: plural(pendingSubnetRoutes, "home.route", "home.routes"),
                  })
                : undefined
            }
          />
        )}
        {node.Features["ssh"] && (
          <SettingsCard
            link="/ssh"
            title="Tailscale SSH server"
            body={t("home.sshDescription")}
            badge={
              node.RunningSSHServer
                ? {
                    text: t("home.running"),
                    icon: <div className="w-2 h-2 bg-green-300 rounded-full" />,
                  }
                : undefined
            }
          />
        )}
        {/* TODO(sonia,will): hiding unimplemented settings pages until implemented */}
        {/* <SettingsCard
        link="/serve"
        title="Share local content"
        body="Share local ports, services, and content to your Tailscale network or to the broader internet."
      /> */}
      </div>
    </div>
  )
}

function SettingsCard({
  title,
  link,
  body,
  badge,
  footer,
  className,
}: {
  title: string
  link: string
  body: string
  badge?: {
    text: string
    icon?: JSX.Element
  }
  footer?: string
  className?: string
}) {
  const [, setLocation] = useLocation()

  return (
    <button onClick={() => setLocation(link)}>
      <Card noPadding className={cx("-mx-5 p-5", className)}>
        <div className="flex justify-between items-center">
          <div>
            <div className="flex gap-2">
              <p className="text-gray-800 font-medium leading-tight mb-2">
                {title}
              </p>
              {badge && (
                <div className="h-5 px-2 bg-gray-100 rounded-full flex items-center gap-2">
                  {badge.icon}
                  <div className="text-gray-500 text-xs font-medium">
                    {badge.text}
                  </div>
                </div>
              )}
            </div>
            <p className="text-gray-500 text-sm leading-tight">{body}</p>
          </div>
          <div>
            <ArrowRight className="ml-3" />
          </div>
        </div>
        {footer && (
          <>
            <hr className="my-3" />
            <div className="text-gray-500 text-sm leading-tight">{footer}</div>
          </>
        )}
      </Card>
    </button>
  )
}
