import React from "react"
import { NodeData } from "src/hooks/node-data"
import { ReactComponent as TailscaleIcon } from "src/icons/tailscale-icon.svg"

/**
 * LoginClientView is rendered when the client is not authenticated
 * to a tailnet.
 */
export default function LoginClientView({
  data,
  onLoginClick,
}: {
  data: NodeData
  onLoginClick: () => void
}) {
  return (
    <div className="mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
      <TailscaleIcon className="my-2 mb-8" />
      {data.IP ? (
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
            onClick={onLoginClick}
            className="button button-blue w-full mb-4"
          >
            Reauthenticate
          </button>
        </>
      ) : (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">Log in</h3>
            <p className="text-gray-700">
              Get started by logging in to your Tailscale network.
              Or,&nbsp;learn&nbsp;more at{" "}
              <a href="https://tailscale.com/" className="link" target="_blank">
                tailscale.com
              </a>
              .
            </p>
          </div>
          <button
            onClick={onLoginClick}
            className="button button-blue w-full mb-4"
          >
            Log In
          </button>
        </>
      )}
    </div>
  )
}
