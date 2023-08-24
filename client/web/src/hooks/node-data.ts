import { useCallback, useEffect, useState } from "react"
import { apiFetch } from "src/api"

export type NodeData = {
  Profile: UserProfile
  Status: string
  DeviceName: string
  IP: string
  AdvertiseExitNode: boolean
  AdvertiseRoutes: string
  LicensesURL: string
  TUNMode: boolean
  IsSynology: boolean
  DSMVersion: number
  IsUnraid: boolean
  UnraidToken: string
  IPNVersion: string
}

export type UserProfile = {
  LoginName: string
  DisplayName: string
  ProfilePicURL: string
}

export type NodeUpdate = {
  AdvertiseRoutes?: string
  AdvertiseExitNode?: boolean
  Reauthenticate?: boolean
  ForceLogout?: boolean
}

// useNodeData returns basic data about the current node.
export default function useNodeData() {
  const [data, setData] = useState<NodeData>()
  const [isPosting, setIsPosting] = useState<boolean>(false)

  const fetchNodeData = useCallback(() => {
    apiFetch("api/data")
      .then((r) => r.json())
      .then((d) => setData(d))
      .catch((error) => console.error(error))
  }, [setData])

  const updateNode = useCallback(
    (update: NodeUpdate) => {
      // The contents of this function are mostly copied over
      // from the legacy client's web.html file.
      // It makes all data updates through one API endpoint.
      // As we build out the web client in React,
      // this endpoint will eventually be deprecated.

      if (isPosting || !data) {
        return
      }
      setIsPosting(true)

      update = {
        ...update,
        // Default to current data value for any unset fields.
        AdvertiseRoutes:
          update.AdvertiseRoutes !== undefined
            ? update.AdvertiseRoutes
            : data.AdvertiseRoutes,
        AdvertiseExitNode:
          update.AdvertiseExitNode !== undefined
            ? update.AdvertiseExitNode
            : data.AdvertiseExitNode,
      }

      const urlParams = new URLSearchParams(window.location.search)
      const nextParams = new URLSearchParams({ up: "true" })
      const token = urlParams.get("SynoToken")
      if (token) {
        nextParams.set("SynoToken", token)
      }
      const search = nextParams.toString()
      const url = `/api/data${search ? `?${search}` : ""}`

      var body, contentType: string

      if (data.IsUnraid) {
        const params = new URLSearchParams()
        params.append("csrf_token", data.UnraidToken)
        params.append("ts_data", JSON.stringify(update))
        body = params.toString()
        contentType = "application/x-www-form-urlencoded;charset=UTF-8"
      } else {
        body = JSON.stringify(update)
        contentType = "application/json"
      }

      apiFetch(url, {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": contentType },
        body: body,
      })
        .then((r) => r.json())
        .then((r) => {
          setIsPosting(false)
          const err = r["error"]
          if (err) {
            throw new Error(err)
          }
          const url = r["url"]
          if (url) {
            window.open(url, "_blank")
          }
          fetchNodeData()
        })
        .catch((err) => alert("Failed operation: " + err.message))
    },
    [data]
  )

  useEffect(
    () => {
      // Initial data load.
      fetchNodeData()

      // Refresh on browser tab focus.
      const onVisibilityChange = () => {
        document.visibilityState === "visible" && fetchNodeData()
      }
      window.addEventListener("visibilitychange", onVisibilityChange)
      return () => {
        // Cleanup browser tab listener.
        window.removeEventListener("visibilitychange", onVisibilityChange)
      }
    },
    // Run once.
    []
  )

  return { data, updateNode, isPosting }
}
