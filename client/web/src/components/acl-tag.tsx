// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { Badge } from "@tailscale/tailscale-ui-components"
import cx from "classnames"
import React from "react"

/**
 * ACLTag handles the display of an ACL tag.
 */
export default function ACLTag({
  tag,
  className,
}: {
  tag: string
  className?: string
}) {
  return (
    <Badge
      variant="status"
      color="outline"
      className={cx("flex text-xs items-center", className)}
    >
      <span className="font-medium">tag:</span>
      <span className="text-gray-500">{tag.replace("tag:", "")}</span>
    </Badge>
  )
}
