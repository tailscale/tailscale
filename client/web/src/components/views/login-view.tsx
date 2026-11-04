// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import { useAPI } from "src/api"
import TailscaleIcon from "src/assets/icons/tailscale-icon.svg?react"
import { NodeData } from "src/types"
import Button from "src/ui/button"
import { useI18n } from "src/i18n"

/**
 * LoginView is rendered when the client is not authenticated
 * to a tailnet.
 */
export default function LoginView({ data }: { data: NodeData }) {
  const api = useAPI()
  const { t } = useI18n()

  return (
    <div className="mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
      <TailscaleIcon className="my-2 mb-8" />
      {data.Status === "Stopped" ? (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">{t("login.connect")}</h3>
            <p className="text-gray-700">
              {t("login.deviceDisconnected")}
            </p>
          </div>
          <Button
            onClick={() => api({ action: "up", data: {} })}
            className="w-full mb-4"
            intent="primary"
          >
            {t("login.connectToTailscale")}
          </Button>
        </>
      ) : data.IPv4 ? (
        <>
          <div className="mb-6">
            <p className="text-gray-700">
              {t("login.keyExpired")} {" "}
              <a
                href="https://tailscale.com/kb/1028/key-expiry"
                className="link"
                target="_blank"
                rel="noreferrer"
              >
                {t("login.learnMore")}
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
            {t("login.reauthenticate")}
          </Button>
        </>
      ) : (
        <>
          <div className="mb-6">
            <h3 className="text-3xl font-semibold mb-3">{t("login.logIn")}</h3>
            <p className="text-gray-700">
              {t("login.logInToNetwork")} {" "}
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
            {t("login.logIn")}
          </Button>
        </>
      )}
    </div>
  )
}
