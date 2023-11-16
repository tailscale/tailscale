import cx from "classnames"
import React from "react"
import { apiFetch } from "src/api"
import { UpdateAvailableNotification } from "src/components/update-available"
import { NodeData } from "src/hooks/node-data"
import { useLocation } from "wouter"
import ACLTag from "../acl-tag"

export default function DeviceDetailsView({
  readonly,
  node,
}: {
  readonly: boolean
  node: NodeData
}) {
  const [, setLocation] = useLocation()

  return (
    <>
      <h1 className="mb-10">Device details</h1>
      <div className="flex flex-col gap-4">
        <div className="card">
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
            <button
              className={cx(
                "px-3 py-2 bg-stone-50 rounded shadow border border-stone-200 text-neutral-800 text-sm font-medium",
                { "cursor-not-allowed": readonly }
              )}
              onClick={() =>
                apiFetch("/local/v0/logout", "POST")
                  .then(() => setLocation("/"))
                  .catch((err) => alert("Logout failed: " + err.message))
              }
              disabled={readonly}
            >
              Disconnect…
            </button>
          </div>
        </div>
        {node.ClientVersion &&
          !node.ClientVersion.RunningLatest &&
          !readonly && (
            <UpdateAvailableNotification details={node.ClientVersion} />
          )}
        <div className="card">
          <h2 className="mb-2">General</h2>
          <table>
            <tbody>
              <tr className="flex">
                <td>Managed by</td>
                <td className="flex gap-1 flex-wrap">
                  {node.IsTagged
                    ? node.Tags.map((t) => <ACLTag key={t} tag={t} />)
                    : node.Profile.DisplayName}
                </td>
              </tr>
              <tr>
                <td>Machine name</td>
                <td>{node.DeviceName}</td>
              </tr>
              <tr>
                <td>OS</td>
                <td>{node.OS}</td>
              </tr>
              <tr>
                <td>ID</td>
                <td>{node.ID}</td>
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
                      new Date(node.KeyExpiry).toLocaleString()}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className="card">
          <h2 className="mb-2">Addresses</h2>
          <table>
            <tbody>
              <tr>
                <td>Tailscale IPv4</td>
                <td>{node.IP}</td>
              </tr>
              <tr>
                <td>Tailscale IPv6</td>
                <td>{node.IPv6}</td>
              </tr>
              <tr>
                <td>Short domain</td>
                <td>{node.DeviceName}</td>
              </tr>
              <tr>
                <td>Full domain</td>
                <td>
                  {node.DeviceName}.{node.TailnetName}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p className="text-neutral-500 text-sm leading-tight text-center">
          Want even more details? Visit{" "}
          <a
            // TODO: pipe control serve url from backend
            href="https://login.tailscale.com/admin"
            target="_blank"
            className="text-indigo-700 text-sm"
          >
            this device’s page
          </a>{" "}
          in the admin console.
        </p>
      </div>
    </>
  )
}
