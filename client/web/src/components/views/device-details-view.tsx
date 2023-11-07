import React from "react"
import { NodeData } from "src/hooks/node-data"
import ProfilePic from "src/ui/profile-pic"

export default function DeviceDetailsView({ node }: { node: NodeData }) {
  return (
    <div>
      <h1 className="mb-10">Device details</h1>
      <div className="flex flex-col gap-4">
        <div className="card">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <h1>{node.DeviceName}</h1>
              {/* TODO: connected status */}
              <div className="w-2.5 h-2.5 bg-emerald-500 rounded-full" />
            </div>
            <button className="px-3 py-2 bg-stone-50 rounded shadow border border-stone-200 text-neutral-800 text-sm font-medium">
              Log out…
            </button>
          </div>
          <hr className="my-5" />
          <div className="text-neutral-500 text-sm leading-tight mb-1">
            Managed by
          </div>
          <div className="flex">
            {/* TODO: tags display */}
            <ProfilePic size="small" url={node.Profile.ProfilePicURL} />
            <div className="ml-2 text-neutral-800 text-sm leading-tight">
              {node.Profile.LoginName}
            </div>
          </div>
        </div>
        <div className="card">
          <h2 className="mb-2">General</h2>
          <table>
            <tbody>
              {/* TODO: pipe through these values */}
              <tr>
                <td>Creator</td>
                <td>{node.Profile.DisplayName}</td>
              </tr>
              <tr>
                <td>Managed by</td>
                <td>{node.Profile.DisplayName}</td>
              </tr>
              <tr>
                <td>Machine name</td>
                <td>{node.DeviceName}</td>
              </tr>
              <tr>
                <td>OS</td>
                <td>MacOS</td>
              </tr>
              <tr>
                <td>ID</td>
                <td>nPKyyg3CNTRL</td>
              </tr>
              <tr>
                <td>Tailscale version</td>
                <td>{node.IPNVersion}</td>
              </tr>
              <tr>
                <td>Key expiry</td>
                <td>3 months from now</td>
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
                <td>fd7a:115c:a1e0:ab12:4843:cd96:627a:f179</td>
              </tr>
              <tr>
                <td>Short domain</td>
                <td>{node.DeviceName}</td>
              </tr>
              <tr>
                <td>Full domain</td>
                <td>{node.DeviceName}.corp.ts.net</td>
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
    </div>
  )
}
