// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { useCallback, useEffect, useMemo, useState } from "react"
import { apiFetch, incrementMetric, setUnraidCsrfToken } from "src/api"
import { ExitNode, noExitNode, runAsExitNode } from "src/hooks/exit-nodes"
import { VersionInfo } from "src/hooks/self-update"
import { assertNever } from "src/utils/util"
import useSWR from "swr"

export type NodeData = {
  Profile: UserProfile
  Status: NodeState
  DeviceName: string
  OS: string
  IPv4: string
  IPv6: string
  ID: string
  KeyExpiry: string
  KeyExpired: boolean
  UsingExitNode?: ExitNode
  AdvertisingExitNode: boolean
  AdvertisedRoutes?: SubnetRoute[]
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
  ControlAdminURL: string
  LicensesURL: string
  Features: { [key in Feature]: boolean } // value is true if given feature is available on this client
  ACLAllowsAnyIncomingTraffic: boolean
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

export type SubnetRoute = {
  Route: string
  Approved: boolean
}

export type Feature =
  | "advertise-exit-node"
  | "advertise-routes"
  | "use-exit-node"
  | "ssh"
  | "auto-update"

export const featureDescription = (f: Feature) => {
  switch (f) {
    case "advertise-exit-node":
      return "Advertising as an exit node"
    case "advertise-routes":
      return "Advertising subnet routes"
    case "use-exit-node":
      return "Using an exit node"
    case "ssh":
      return "Running a Tailscale SSH server"
    case "auto-update":
      return "Auto updating client versions"
    default:
      assertNever(f)
  }
}

/**
 * NodeUpdaters provides a set of mutation functions for a node.
 *
 * These functions handle both making the requested change, as well as
 * refreshing the app's node data state upon completion to reflect any
 * relevant changes in the UI.
 */
export type NodeUpdaters = {
  /**
   * patchPrefs updates node preferences.
   * Only provided preferences will be updated.
   * Similar to running the tailscale set command in the CLI.
   */
  patchPrefs: (d: PrefsPATCHData) => Promise<void>
  /**
   * postExitNode updates the node's status as either using or
   * running as an exit node.
   */
  postExitNode: (d: ExitNode) => Promise<void>
  /**
   * postSubnetRoutes updates the node's advertised subnet routes.
   */
  postSubnetRoutes: (d: string[]) => Promise<void>
}

type PrefsPATCHData = {
  RunSSHSet?: boolean
  RunSSH?: boolean
}

type RoutesPOSTData = {
  UseExitNode?: string
  AdvertiseExitNode?: boolean
  AdvertiseRoutes?: string[]
}

// useNodeData returns basic data about the current node.
export default function useNodeData() {
  const { data, mutate } = useSWR<NodeData>("/data")
  const [isPosting, setIsPosting] = useState<boolean>(false)

  useEffect(
    () => setUnraidCsrfToken(data?.IsUnraid ? data.UnraidToken : undefined),
    [data]
  )

  const prefsPATCH = useCallback(
    (d: PrefsPATCHData) => {
      setIsPosting(true)
      if (data) {
        const optimisticUpdates = data
        if (d.RunSSHSet) {
          optimisticUpdates.RunningSSHServer = Boolean(d.RunSSH)
        }
        // Reflect the pref change immediatley on the frontend,
        // then make the prefs PATCH. If the request fails,
        // data will be updated to it's previous value in
        // onComplete below.
        mutate(optimisticUpdates, false)
      }

      const onComplete = () => {
        setIsPosting(false)
        mutate() // refresh data after PATCH finishes
      }

      return apiFetch("/local/v0/prefs", "PATCH", d)
        .then(onComplete)
        .catch((err) => {
          onComplete()
          alert("Failed to update prefs")
          throw err
        })
    },
    [data, mutate]
  )

  const routesPOST = useCallback(
    (d: RoutesPOSTData) => {
      setIsPosting(true)
      const onComplete = () => {
        setIsPosting(false)
        mutate() // refresh data after POST finishes
      }
      const updateMetrics = () => {
        // only update metrics if values have changed
        if (data?.AdvertisingExitNode !== d.AdvertiseExitNode) {
          incrementMetric(
            d.AdvertiseExitNode
              ? "web_client_advertise_exitnode_enable"
              : "web_client_advertise_exitnode_disable"
          )
        }
      }

      return apiFetch("/routes", "POST", d)
        .then(() => {
          updateMetrics()
          onComplete()
        })
        .catch((err) => {
          onComplete()
          alert("Failed to update routes")
          throw err
        })
    },
    [mutate, data?.AdvertisingExitNode]
  )

  const nodeUpdaters: NodeUpdaters = useMemo(
    () => ({
      patchPrefs: prefsPATCH,
      postExitNode: (node) =>
        routesPOST({
          AdvertiseExitNode: node.ID === runAsExitNode.ID,
          UseExitNode:
            node.ID === noExitNode.ID || node.ID === runAsExitNode.ID
              ? undefined
              : node.ID,
          AdvertiseRoutes: data?.AdvertisedRoutes?.map((r) => r.Route), // unchanged
        }),
      postSubnetRoutes: (routes) =>
        routesPOST({
          AdvertiseRoutes: routes,
          AdvertiseExitNode: data?.AdvertisingExitNode, // unchanged
          UseExitNode: data?.UsingExitNode?.ID, // unchanged
        }),
    }),
    [
      data?.AdvertisingExitNode,
      data?.AdvertisedRoutes,
      data?.UsingExitNode?.ID,
      prefsPATCH,
      routesPOST,
    ]
  )

  return { data, refreshData: mutate, nodeUpdaters, isPosting }
}
