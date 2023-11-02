import { useCallback, useEffect, useState } from "react"
import { apiFetch, setSynoToken } from "src/api"

export enum AuthType {
  synology = "synology",
  tailscale = "tailscale",
}

export type AuthResponse = {
  ok: boolean
  authUrl?: string
  authNeeded?: AuthType
}

// useAuth reports and refreshes Tailscale auth status
// for the web client.
export default function useAuth() {
  const [data, setData] = useState<AuthResponse>()
  const [loading, setLoading] = useState<boolean>(true)

  const loadAuth = useCallback((wait?: boolean) => {
    const url = wait ? "/auth?wait=true" : "/auth"
    setLoading(true)
    return apiFetch(url, "GET")
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
      })
      .catch((error) => {
        setLoading(false)
        console.error(error)
      })
  }, [])

  useEffect(() => {
    loadAuth()
  }, [])

  const waitOnAuth = useCallback(() => loadAuth(true), [])

  return { data, loading, waitOnAuth }
}
