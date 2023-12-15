// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import { NodeData } from "src/types"

/**
 * AdminContainer renders its contents only if the node's control
 * server has an admin panel.
 *
 * TODO(sonia,will): Similarly, this could also hide the contents
 * if the viewing user is a non-admin.
 */
export function AdminContainer({
  node,
  children,
  className,
}: {
  node: NodeData
  children: React.ReactNode
  className?: string
}) {
  if (!node.ControlAdminURL.includes("tailscale.com")) {
    // Admin panel only exists on Tailscale control servers.
    return null
  }
  return <div className={className}>{children}</div>
}

/**
 * AdminLink renders its contents wrapped in a link to the node's control
 * server admin panel.
 *
 * AdminLink is meant for use only inside of a AdminContainer component,
 * to avoid rendering a link when the node's control server does not have
 * an admin panel.
 */
export function AdminLink({
  node,
  children,
  path,
}: {
  node: NodeData
  children: React.ReactNode
  path: string // admin path, e.g. "/settings/webhooks"
}) {
  return (
    <a
      href={`${node.ControlAdminURL}${path}`}
      className="link"
      target="_blank"
      rel="noreferrer"
    >
      {children}
    </a>
  )
}
