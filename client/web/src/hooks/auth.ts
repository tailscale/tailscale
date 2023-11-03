import { useCallback, useEffect, useState } from "react"
import { apiFetch, setSynoToken } from "src/api"

export enum AuthType {
  synology = "synology",
  tailscale = "tailscale",
}

export type AuthResponse = {
  ok: boolean
  authNeeded?: AuthType
}

export type SessionsCallbacks = {
  new: () => Promise<string> // creates new auth session and returns authURL
  wait: () => Promise<void> // blocks until auth is completed
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
      })
      .catch((error) => {
        setLoading(false)
        console.error(error)
      })
  }, [])

  const newSession = useCallback(() => {
    return apiFetch("/auth/session/new", "GET")
      .then((r) => r.json())
      .then((d) => d.authUrl)
      .catch((error) => {
        console.error(error)
      })
  }, [])

  const waitForSessionCompletion = useCallback(() => {
    return apiFetch("/auth/session/wait", "GET")
      .then(() => loadAuth()) // refresh auth data
      .catch((error) => {
        console.error(error)
      })
  }, [])

  useEffect(() => {
    loadAuth()
  }, [])

  return {
    data,
    loading,
    sessions: {
      new: newSession,
      wait: waitForSessionCompletion,
    },
  }
}
