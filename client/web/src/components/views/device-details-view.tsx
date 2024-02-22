// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React from "react"
import { useAPI } from "src/api"
import ACLTag from "src/components/acl-tag"
import * as Control from "src/components/control-components"
import NiceIP from "src/components/nice-ip"
import { UpdateAvailableNotification } from "src/components/update-available"
import { AuthResponse, canEdit } from "src/hooks/auth"
import { NodeData } from "src/types"
import Button from "src/ui/button"
import Card from "src/ui/card"
import Dialog from "src/ui/dialog"
import QuickCopy from "src/ui/quick-copy"
import { useLocation } from "wouter"

export default function DeviceDetailsView({
  node,
  auth,
}: {
  node: NodeData
  auth: AuthResponse
}) {
  return (
    <>
      <h1 className="mb-10">Device details</h1>
      <div className="flex flex-col gap-4">
        <Card noPadding className="-mx-5 p-5 details-card">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h1>{node.DeviceName}</h1>
              <div
                className={cx("w-2.5 h-2.5 rounded-full", {
                  "bg-emerald-500": node.Status === "Running",
                  "bg-gray-300": node.Status !== "Running",
                })}
              />
            </div>
            {canEdit("account", auth) && <DisconnectDialog />}
          </div>
        </Card>
        {node.Features["auto-update"] &&
          canEdit("account", auth) &&
          node.ClientVersion &&
          !node.ClientVersion.RunningLatest && (
            <UpdateAvailableNotification details={node.ClientVersion} />
          )}
        <Card noPadding className="-mx-5 p-5 details-card">
          <h2 className="mb-2">General</h2>
          <table>
            <tbody>
              <tr className="flex">
                <td>Managed by</td>
                <td className="flex gap-1 flex-wrap">
                  {node.IsTagged
                    ? node.Tags.map((t) => <ACLTag key={t} tag={t} />)
                    : node.Profile?.DisplayName}
                </td>
              </tr>
              <tr>
                <td>Machine name</td>
                <td>
                  <QuickCopy
                    primaryActionValue={node.DeviceName}
                    primaryActionSubject="machine name"
                  >
                    {node.DeviceName}
                  </QuickCopy>
                </td>
              </tr>
              <tr>
                <td>OS</td>
                <td>{node.OS}</td>
              </tr>
              <tr>
                <td>ID</td>
                <td>
                  <QuickCopy
                    primaryActionValue={node.ID}
                    primaryActionSubject="ID"
                  >
                    {node.ID}
                  </QuickCopy>
                </td>
              </tr>
              <tr>
                <td>Tailscale version</td>
                <td>{node.IPNVersion}</td>
              </tr>
              <tr>
                <td>Key expiry</td>
                <td>
                  {node.KeyExpired
                    ? "Expired"
                    : // TODO: present as relative expiry (e.g. "5 months from now")
                    node.KeyExpiry
                    ? new Date(node.KeyExpiry).toLocaleString()
                    : "No expiry"}
                </td>
              </tr>
            </tbody>
          </table>
        </Card>
        <Card noPadding className="-mx-5 p-5 details-card">
          <h2 className="mb-2">Addresses</h2>
          <table>
            <tbody>
              <tr>
                <td>Tailscale IPv4</td>
                <td>
                  <QuickCopy
                    primaryActionValue={node.IPv4}
                    primaryActionSubject="IPv4 address"
                  >
                    {node.IPv4}
                  </QuickCopy>
                </td>
              </tr>
              <tr>
                <td>Tailscale IPv6</td>
                <td>
                  <QuickCopy
                    primaryActionValue={node.IPv6}
                    primaryActionSubject="IPv6 address"
                  >
                    <NiceIP ip={node.IPv6} />
                  </QuickCopy>
                </td>
              </tr>
              <tr>
                <td>Short domain</td>
                <td>
                  <QuickCopy
                    primaryActionValue={node.DeviceName}
                    primaryActionSubject="short domain"
                  >
                    {node.DeviceName}
                  </QuickCopy>
                </td>
              </tr>
              <tr>
                <td>Full domain</td>
                <td>
                  <QuickCopy
                    primaryActionValue={`${node.DeviceName}.${node.TailnetName}`}
                    primaryActionSubject="full domain"
                  >
                    {node.DeviceName}.{node.TailnetName}
                  </QuickCopy>
                </td>
              </tr>
            </tbody>
          </table>
        </Card>
        <Card noPadding className="-mx-5 p-5 details-card">
          <h2 className="mb-2">Debug</h2>
          <table>
            <tbody>
              <tr>
                <td>TUN Mode</td>
                <td>{node.TUNMode ? "Yes" : "No"}</td>
              </tr>
              {node.IsSynology && (
                <tr>
                  <td>Synology Version</td>
                  <td>{node.DSMVersion}</td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>
        <footer className="text-gray-500 text-sm leading-tight text-center">
          <Control.AdminContainer node={node}>
            Want even more details? Visit{" "}
            <Control.AdminLink node={node} path={`/machines/${node.IPv4}`}>
              this device’s page
            </Control.AdminLink>{" "}
            in the admin console.
          </Control.AdminContainer>
          <p className="mt-12">
            <a
              className="link"
              href={node.LicensesURL}
              target="_blank"
              rel="noreferrer"
            >
              Acknowledgements
            </a>{" "}
            ·{" "}
            <a
              className="link"
              href="https://tailscale.com/privacy-policy/"
              target="_blank"
              rel="noreferrer"
            >
              Privacy Policy
            </a>{" "}
            ·{" "}
            <a
              className="link"
              href="https://tailscale.com/terms/"
              target="_blank"
              rel="noreferrer"
            >
              Terms of Service
            </a>
          </p>
          <p className="my-2">
            WireGuard is a registered trademark of Jason A. Donenfeld.
          </p>
          <p>
            © {new Date().getFullYear()} Tailscale Inc. All rights reserved.
            Tailscale is a registered trademark of Tailscale Inc.
          </p>
        </footer>
      </div>
    </>
  )
}

function DisconnectDialog() {
  const api = useAPI()
  const [, setLocation] = useLocation()

  return (
    <Dialog
      className="max-w-md"
      title="Log out"
      trigger={<Button sizeVariant="small">Log out…</Button>}
    >
      <Dialog.Form
        cancelButton
        submitButton="Log out"
        destructive
        onSubmit={() => {
          api({ action: "logout" })
          setLocation("/disconnected")
        }}
      >
        Logging out of this device will disconnect it from your tailnet and
        expire its node key. You won’t be able to use this web interface until
        you re-authenticate the device from either the Tailscale app or the
        Tailscale command line interface.
      </Dialog.Form>
    </Dialog>
  )
}
