import cx from "classnames"
import React from "react"
import { apiFetch } from "src/api"
import { NodeData, NodeUpdate } from "src/hooks/node-data"

// TODO(tailscale/corp#13775): legacy.tsx contains a set of components
// that (crudely) implement the pre-2023 web client. These are implemented
// purely to ease migration to the new React-based web client, and will
// eventually be completely removed.

export function Header({
  data,
  refreshData,
  updateNode,
}: {
  data: NodeData
  refreshData: () => void
  updateNode: (update: NodeUpdate) => void
}) {
  return (
    <header className="flex justify-between items-center min-width-0 py-2 mb-8">
      <svg
        width="26"
        height="26"
        viewBox="0 0 23 23"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        className="flex-shrink-0 mr-4"
      >
        <circle
          opacity="0.2"
          cx="3.4"
          cy="3.25"
          r="2.7"
          fill="currentColor"
        ></circle>
        <circle cx="3.4" cy="11.3" r="2.7" fill="currentColor"></circle>
        <circle
          opacity="0.2"
          cx="3.4"
          cy="19.5"
          r="2.7"
          fill="currentColor"
        ></circle>
        <circle cx="11.5" cy="11.3" r="2.7" fill="currentColor"></circle>
        <circle cx="11.5" cy="19.5" r="2.7" fill="currentColor"></circle>
        <circle
          opacity="0.2"
          cx="11.5"
          cy="3.25"
          r="2.7"
          fill="currentColor"
        ></circle>
        <circle
          opacity="0.2"
          cx="19.5"
          cy="3.25"
          r="2.7"
          fill="currentColor"
        ></circle>
        <circle cx="19.5" cy="11.3" r="2.7" fill="currentColor"></circle>
        <circle
          opacity="0.2"
          cx="19.5"
          cy="19.5"
          r="2.7"
          fill="currentColor"
        ></circle>
      </svg>
      <div className="flex items-center justify-end space-x-2 w-2/3">
        {data.Profile &&
          data.Status !== "NoState" &&
          data.Status !== "NeedsLogin" && (
            <>
              <div className="text-right w-full leading-4">
                <h4 className="truncate leading-normal">
                  {data.Profile.LoginName}
                </h4>
                <div className="text-xs text-gray-500 text-right">
                  <button
                    onClick={() => updateNode({ Reauthenticate: true })}
                    className="hover:text-gray-700"
                  >
                    Switch account
                  </button>{" "}
                  |{" "}
                  <button
                    onClick={() => updateNode({ Reauthenticate: true })}
                    className="hover:text-gray-700"
                  >
                    Reauthenticate
                  </button>{" "}
                  |{" "}
                  <button
                    onClick={() =>
                      apiFetch("/local/v0/logout", "POST")
                        .then(refreshData)
                        .catch((err) => alert("Logout failed: " + err.message))
                    }
                    className="hover:text-gray-700"
                  >
                    Logout
                  </button>
                </div>
              </div>
              <div className="relative flex-shrink-0 w-8 h-8 rounded-full overflow-hidden">
                {data.Profile.ProfilePicURL ? (
                  <div
                    className="w-8 h-8 flex pointer-events-none rounded-full bg-gray-200"
                    style={{
                      backgroundImage: `url(${data.Profile.ProfilePicURL})`,
                      backgroundSize: "cover",
                    }}
                  />
                ) : (
                  <div className="w-8 h-8 flex pointer-events-none rounded-full border border-gray-400 border-dashed" />
                )}
              </div>
            </>
          )}
      </div>
    </header>
  )
}

export function IP(props: { data: NodeData }) {
  const { data } = props

  if (!data.IP) {
    return null
  }

  return (
    <>
      <div className="border border-gray-200 bg-gray-50 rounded-md p-2 pl-3 pr-3 width-full flex items-center justify-between">
        <div className="flex items-center min-width-0">
          <svg
            className="flex-shrink-0 text-gray-600 mr-3 ml-1"
            xmlns="http://www.w3.org/2000/svg"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
            <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
            <line x1="6" y1="6" x2="6.01" y2="6"></line>
            <line x1="6" y1="18" x2="6.01" y2="18"></line>
          </svg>
          <h4 className="font-semibold truncate mr-2">
            {data.DeviceName || "Your device"}
          </h4>
        </div>
        <h5>{data.IP}</h5>
      </div>
      <p className="mt-1 ml-1 mb-6 text-xs text-gray-600">
        Debug info: Tailscale {data.IPNVersion}, tun={data.TUNMode.toString()}
        {data.IsSynology && (
          <>
            , DSM{data.DSMVersion}
            {data.TUNMode || (
              <>
                {" "}
                (
                <a
                  href="https://tailscale.com/kb/1152/synology-outbound/"
                  className="link-underline text-gray-600"
                  target="_blank"
                  aria-label="Configure outbound synology traffic"
                  rel="noopener noreferrer"
                >
                  outgoing access not configured
                </a>
                )
              </>
            )}
          </>
        )}
      </p>
    </>
  )
}

export function State({
  data,
  updateNode,
}: {
  data: NodeData
  updateNode: (update: NodeUpdate) => void
}) {
  switch (data.Status) {
    case "NeedsLogin":
    case "NoState":
      if (data.IP) {
        return (
          <>
            <div className="mb-6">
              <p className="text-gray-700">
                Your device's key has expired. Reauthenticate this device by
                logging in again, or{" "}
                <a
                  href="https://tailscale.com/kb/1028/key-expiry"
                  className="link"
                  target="_blank"
                >
                  learn more
                </a>
                .
              </p>
            </div>
            <button
              onClick={() => updateNode({ Reauthenticate: true })}
              className="button button-blue w-full mb-4"
            >
              Reauthenticate
            </button>
          </>
        )
      } else {
        return (
          <>
            <div className="mb-6">
              <h3 className="text-3xl font-semibold mb-3">Log in</h3>
              <p className="text-gray-700">
                Get started by logging in to your Tailscale network.
                Or,&nbsp;learn&nbsp;more at{" "}
                <a
                  href="https://tailscale.com/"
                  className="link"
                  target="_blank"
                >
                  tailscale.com
                </a>
                .
              </p>
            </div>
            <button
              onClick={() => updateNode({ Reauthenticate: true })}
              className="button button-blue w-full mb-4"
            >
              Log In
            </button>
          </>
        )
      }
    case "NeedsMachineAuth":
      return (
        <div className="mb-4">
          This device is authorized, but needs approval from a network admin
          before it can connect to the network.
        </div>
      )
    default:
      return (
        <>
          <div className="mb-4">
            <p>
              You are connected! Access this device over Tailscale using the
              device name or IP address above.
            </p>
          </div>
          <button
            className={cx("button button-medium mb-4", {
              "button-red": data.AdvertiseExitNode,
              "button-blue": !data.AdvertiseExitNode,
            })}
            id="enabled"
            onClick={() =>
              updateNode({ AdvertiseExitNode: !data.AdvertiseExitNode })
            }
          >
            {data.AdvertiseExitNode
              ? "Stop advertising Exit Node"
              : "Advertise as Exit Node"}
          </button>
        </>
      )
  }
}

export function Footer(props: { data: NodeData }) {
  const { data } = props

  return (
    <footer className="container max-w-lg mx-auto text-center">
      <a
        className="text-xs text-gray-500 hover:text-gray-600"
        href={data.LicensesURL}
      >
        Open Source Licenses
      </a>
    </footer>
  )
}
