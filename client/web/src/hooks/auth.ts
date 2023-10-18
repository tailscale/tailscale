import { useCallback, useEffect, useState } from "react"
import { apiFetch } from "src/api"

export type AuthResponse = {
  ok: boolean
  authUrl?: string
}

// useAuth reports and refreshes Tailscale auth status
// for the web client.
export default function useAuth() {
  const [data, setData] = useState<AuthResponse>()
  const [loading, setLoading] = useState<boolean>(false)

  const loadAuth = useCallback((wait?: boolean) => {
    const url = wait ? "/auth?wait=true" : "/auth"
    setLoading(true)
    return apiFetch(url, "GET")
      .then((r) => r.json())
      .then((d) => {
        setLoading(false)
        setData(d)
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
