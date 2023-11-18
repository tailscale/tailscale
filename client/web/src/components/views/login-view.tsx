import React, { useCallback, useState } from "react"
import { apiFetch } from "src/api"
import { ReactComponent as TailscaleIcon } from "src/assets/icons/tailscale-icon.svg"
import { NodeData } from "src/hooks/node-data"
import Collapsible from "src/ui/collapsible"
import Input from "src/ui/input"

/**
 * LoginView is rendered when the client is not authenticated
 * to a tailnet.
 */
export default function LoginView({
  data,
  refreshData,
}: {
  data: NodeData
  refreshData: () => void
}) {
  const [controlURL, setControlURL] = useState<string>("")
  const [authKey, setAuthKey] = useState<string>("")

  const login = useCallback(
    (opt: TailscaleUpOptions) => {
      tailscaleUp(opt).then(refreshData)
    },
    [refreshData]
  )

  return (
    <div className="mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
      <TailscaleIcon className="my-2 mb-8" />
      {data.Status == "Stopped" ? (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">Connect</h3>
            <p className="text-gray-700">
              Your device is disconnected from Tailscale.
            </p>
          </div>
          <button
            onClick={() => login({})}
            className="button button-blue w-full mb-4"
          >
            Connect to Tailscale
          </button>
        </>
      ) : data.IP ? (
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
            onClick={() => login({ Reauthenticate: true })}
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
            onClick={() =>
              login({
                Reauthenticate: true,
                ControlURL: controlURL,
                AuthKey: authKey,
              })
            }
            className="button button-blue w-full mb-4"
          >
            Log In
          </button>
          <Collapsible trigger="Advanced options">
            <h4 className="font-medium mb-1 mt-2">Auth Key</h4>
            <p className="text-sm text-gray-500">
              Connect with a pre-authenticated key.{" "}
              <a
                href="https://tailscale.com/kb/1085/auth-keys/"
                className="link"
                target="_blank"
              >
                Learn more &rarr;
              </a>
            </p>
            <Input
              className="mt-2"
              value={authKey}
              onChange={(e) => setAuthKey(e.target.value)}
              placeholder="tskey-auth-XXX"
            />
            <h4 className="font-medium mt-3 mb-1">Server URL</h4>
            <p className="text-sm text-gray-500">Base URL of control server.</p>
            <Input
              className="mt-2"
              value={controlURL}
              onChange={(e) => setControlURL(e.target.value)}
              placeholder="https://login.tailscale.com/"
            />
          </Collapsible>
        </>
      )}
    </div>
  )
}

type TailscaleUpOptions = {
  Reauthenticate?: boolean // force reauthentication
  ControlURL?: string
  AuthKey?: string
}

function tailscaleUp(options: TailscaleUpOptions) {
  return apiFetch("/up", "POST", options)
    .then((r) => r.json())
    .then((d) => {
      d.url && window.open(d.url, "_blank")
    })
    .catch((e) => {
      console.error("Failed to login:", e)
    })
}
