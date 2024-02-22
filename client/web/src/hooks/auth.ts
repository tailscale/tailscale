// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { useCallback, useEffect, useState } from "react"
import { apiFetch, setSynoToken } from "src/api"

export type AuthResponse = {
  serverMode: AuthServerMode
  authorized: boolean
  viewerIdentity?: {
    loginName: string
    nodeName: string
    nodeIP: string
    profilePicUrl?: string
    capabilities: { [key in PeerCapability]: boolean }
  }
  needsSynoAuth?: boolean
}

export type AuthServerMode = "login" | "readonly" | "manage"

export type PeerCapability = "*" | "ssh" | "subnets" | "exitnodes" | "account"

/**
 * canEdit reports whether the given auth response specifies that the viewer
 * has the ability to edit the given capability.
 */
export function canEdit(cap: PeerCapability, auth: AuthResponse): boolean {
  if (!auth.authorized || !auth.viewerIdentity) {
    return false
  }
  if (auth.viewerIdentity.capabilities["*"] === true) {
    return true // can edit all features
  }
  return auth.viewerIdentity.capabilities[cap] === true
}

/**
 * hasAnyEditCapabilities reports whether the given auth response specifies
 * that the viewer has at least one edit capability. If this is true, the
 * user is able to go through the auth flow to authenticate a management
 * session.
 */
export function hasAnyEditCapabilities(auth: AuthResponse): boolean {
  return Object.values(auth.viewerIdentity?.capabilities || {}).includes(true)
}

/**
 * useAuth reports and refreshes Tailscale auth status for the web client.
 */
export default function useAuth() {
  const [data, setData] = useState<AuthResponse>()
  const [loading, setLoading] = useState<boolean>(true)
  const [ranSynoAuth, setRanSynoAuth] = useState<boolean>(false)

  const loadAuth = useCallback(() => {
    setLoading(true)
    return apiFetch<AuthResponse>("/auth", "GET")
      .then((d) => {
        setData(d)
        if (d.needsSynoAuth) {
          fetch("/webman/login.cgi")
            .then((r) => r.json())
            .then((a) => {
              setSynoToken(a.SynoToken)
              setRanSynoAuth(true)
              setLoading(false)
            })
        } else {
          setLoading(false)
        }
        return d
      })
      .catch((error) => {
        setLoading(false)
        console.error(error)
      })
  }, [])

  const newSession = useCallback(() => {
    return apiFetch<{ authUrl?: string }>("/auth/session/new", "GET")
      .then((d) => {
        if (d.authUrl) {
          window.open(d.authUrl, "_blank")
          return apiFetch("/auth/session/wait", "GET")
        }
      })
      .then(() => {
        loadAuth()
      })
      .catch((error) => {
        console.error(error)
      })
  }, [loadAuth])

  useEffect(() => {
    loadAuth().then((d) => {
      if (!d) {
        return
      }
      if (
        !d.authorized &&
        hasAnyEditCapabilities(d) &&
        // Start auth flow immediately if browser has requested it.
        new URLSearchParams(window.location.search).get("check") === "now"
      ) {
        newSession()
      }
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    loadAuth() // Refresh auth state after syno auth runs
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ranSynoAuth])

  return {
    data,
    loading,
    newSession,
  }
}
