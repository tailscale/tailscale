// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { useEffect } from "react"
import { getAuthSessionNew, setSynoToken } from "src/api"
import useSWR from "swr"

export enum AuthType {
  synology = "synology",
  tailscale = "tailscale",
}

export type AuthResponse = {
  authNeeded?: AuthType
  canManageNode: boolean
  viewerIdentity?: {
    loginName: string
    nodeName: string
    nodeIP: string
    profilePicUrl?: string
  }
}

// useAuth reports and refreshes Tailscale auth status
// for the web client.
export default function useAuth() {
  const { data, isLoading, mutate } = useSWR<AuthResponse>("/auth")

  useEffect(() => {
    if (data?.authNeeded === AuthType.synology) {
      fetch("/webman/login.cgi")
        .then((r) => r.json())
        .then((a) => {
          setSynoToken(a.SynoToken)
          // Refresh auth reponse once synology
          // auth completed.
          mutate()
        })
    }
  })

  // TODO
  useEffect(() => {
    loadAuth().then((d) => {
      if (
        !d.canManageNode &&
        new URLSearchParams(window.location.search).get("check") === "now"
      ) {
        getAuthSessionNew()
      }
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return {
    data,
    loading: isLoading || data?.authNeeded === AuthType.synology,
  }
}
