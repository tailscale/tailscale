// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import { useAPI } from "src/api"
import TailscaleIcon from "src/assets/icons/tailscale-icon.svg?react"
import { NodeData } from "src/types"
import Button from "src/ui/button"

/**
 * LoginView is rendered when the client is not authenticated
 * to a tailnet.
 */
export default function LoginView({ data }: { data: NodeData }) {
  const api = useAPI()

  return (
    <div className="mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
      <TailscaleIcon className="my-2 mb-8" />
      {data.Status === "Stopped" ? (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">Connect</h3>
            <p className="text-gray-700">
              Your device is disconnected from Tailscale.
            </p>
          </div>
          <Button
            onClick={() => api({ action: "up", data: {} })}
            className="w-full mb-4"
            intent="primary"
          >
            Connect to Tailscale
          </Button>
        </>
      ) : data.IPv4 ? (
        <>
          <div className="mb-6">
            <p className="text-gray-700">
              Your device’s key has expired. Reauthenticate this device by
              logging in again, or{" "}
              <a
                href="https://tailscale.com/kb/1028/key-expiry"
                className="link"
                target="_blank"
                rel="noreferrer"
              >
                learn more
              </a>
              .
            </p>
          </div>
          <Button
            onClick={() =>
              api({ action: "up", data: { Reauthenticate: true } })
            }
            className="w-full mb-4"
            intent="primary"
          >
            Reauthenticate
          </Button>
        </>
      ) : (
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
                rel="noreferrer"
              >
                tailscale.com
              </a>
              .
            </p>
          </div>
          <Button
            onClick={() =>
              api({
                action: "up",
                data: {
                  Reauthenticate: true,
                },
              })
            }
            className="w-full mb-4"
            intent="primary"
          >
            Log In
          </Button>
        </>
      )}
    </div>
  )
}
