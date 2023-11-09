import { useCallback, useEffect, useState } from "react"
import { apiFetch, setUnraidCsrfToken } from "src/api"

export type NodeData = {
  Profile: UserProfile
  Status: NodeState
  DeviceName: string
  OS: string
  IP: string
  IPv6: string
  ID: string
  KeyExpiry: string
  KeyExpired: boolean
  AdvertiseExitNode: boolean
  AdvertiseRoutes: string
  LicensesURL: string
  TUNMode: boolean
  IsSynology: boolean
  DSMVersion: number
  IsUnraid: boolean
  UnraidToken: string
  IPNVersion: string
  URLPrefix: string
  DomainName: string
  TailnetName: string
  IsTagged: boolean
  Tags: string[]

  DebugMode: "" | "login" | "full" // empty when not running in any debug mode
}

type NodeState =
  | "NoState"
  | "NeedsLogin"
  | "NeedsMachineAuth"
  | "Stopped"
  | "Starting"
  | "Running"

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

  const refreshData = useCallback(
    () =>
      apiFetch("/data", "GET")
        .then((r) => r.json())
        .then((d: NodeData) => {
          setData(d)
          setUnraidCsrfToken(d.IsUnraid ? d.UnraidToken : undefined)
        })
        .catch((error) => console.error(error)),
    [setData]
  )

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

      return apiFetch("/data", "POST", update, { up: "true" })
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
          refreshData()
        })
        .catch((err) => {
          alert("Failed operation: " + err.message)
          throw err
        })
    },
    [data]
  )

  useEffect(
    () => {
      // Initial data load.
      refreshData()

      // Refresh on browser tab focus.
      const onVisibilityChange = () => {
        document.visibilityState === "visible" && refreshData()
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

  return { data, refreshData, updateNode, isPosting }
}
