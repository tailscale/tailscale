import { useCallback, useEffect, useState } from "react"
import { apiFetch, setUnraidCsrfToken } from "src/api"
import { ExitNode } from "src/hooks/exit-nodes"
import { VersionInfo } from "src/hooks/self-update"

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
  ClientVersion?: VersionInfo
  URLPrefix: string
  DomainName: string
  TailnetName: string
  IsTagged: boolean
  Tags: string[]
  RunningSSHServer: boolean
  ExitNodeStatus?: ExitNode & { Online: boolean }
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
}

export type PrefsUpdate = {
  RunSSHSet?: boolean
  RunSSH?: boolean
  ExitNodeIDSet?: boolean
  ExitNodeID?: string
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
          refreshData()
        })
        .catch((err) => {
          setIsPosting(false)
          alert("Failed operation: " + err.message)
          throw err
        })
    },
    [data]
  )

  const updatePrefs = useCallback(
    (p: PrefsUpdate) => {
      setIsPosting(true)
      if (data) {
        const optimisticUpdates = data
        if (p.RunSSHSet) {
          optimisticUpdates.RunningSSHServer = Boolean(p.RunSSH)
        }
        // Reflect the pref change immediatley on the frontend,
        // then make the prefs PATCH. If the request fails,
        // data will be updated to it's previous value in
        // onComplete below.
        setData(optimisticUpdates)
      }

      const onComplete = () => {
        setIsPosting(false)
        refreshData() // refresh data after PATCH finishes
      }

      return apiFetch("/local/v0/prefs", "PATCH", p)
        .then(onComplete)
        .catch(() => {
          onComplete()
          alert("Failed to update prefs")
        })
    },
    [setIsPosting, refreshData, setData, data]
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

  return { data, refreshData, updateNode, updatePrefs, isPosting }
}
