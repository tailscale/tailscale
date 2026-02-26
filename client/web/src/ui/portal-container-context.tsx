// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"

const PortalContainerContext = React.createContext<HTMLElement | undefined>(
  undefined
)
export default PortalContainerContext
