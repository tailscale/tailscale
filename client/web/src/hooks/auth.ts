import { useCallback, useEffect, useState } from "react"
import { apiFetch, setSynoToken } from "src/api"

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
  const [data, setData] = useState<AuthResponse>()
  const [loading, setLoading] = useState<boolean>(true)

  const loadAuth = useCallback(() => {
    setLoading(true)
    return apiFetch("/auth", "GET")
      .then((r) => r.json())
      .then((d) => {
        setData(d)
        switch ((d as AuthResponse).authNeeded) {
          case AuthType.synology:
            fetch("/webman/login.cgi")
              .then((r) => r.json())
              .then((a) => {
                setSynoToken(a.SynoToken)
                setLoading(false)
              })
            break
          default:
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
    return apiFetch("/auth/session/new", "GET")
      .then((r) => r.json())
      .then((d) => {
        if (d.authUrl) {
          window.open(d.authUrl, "_blank")
          // refresh data when auth complete
          apiFetch("/auth/session/wait", "GET").then(() => loadAuth())
        }
      })
      .catch((error) => {
        console.error(error)
      })
  }, [])

  useEffect(() => {
    loadAuth().then((d) => {
      if (
        !d.canManageNode &&
        new URLSearchParams(window.location.search).get("check") == "now"
      ) {
        newSession()
      }
    })
  }, [])

  return {
    data,
    loading,
    newSession,
  }
}
