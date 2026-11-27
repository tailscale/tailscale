// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import TailscaleIcon from "src/assets/icons/tailscale-icon.svg?react"
import { t } from "src/i18n"

/**
 * DisconnectedView is rendered after node logout.
 */
export default function DisconnectedView() {
  return (
    <>
      <TailscaleIcon className="mx-auto" />
      <p className="mt-12 text-center text-text-muted">{t("loggedOut")}</p>
    </>
  )
}
