// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { useCallback } from "react"
import useToaster from "src/hooks/toaster"
import { ExitNode, NodeData, SubnetRoute } from "src/types"
import { assertNever } from "src/utils/util"
import { MutatorOptions, SWRConfiguration, useSWRConfig } from "swr"
import { noExitNode, runAsExitNode } from "./hooks/exit-nodes"

export const swrConfig: SWRConfiguration = {
  fetcher: (url: string) => apiFetch(url, "GET"),
  onError: (err, _) => console.error(err),
}

type APIType =
  | { action: "up"; data: TailscaleUpData }
  | { action: "logout" }
  | { action: "new-auth-session"; data: AuthSessionNewData }
  | { action: "update-prefs"; data: LocalPrefsData }
  | { action: "update-routes"; data: SubnetRoute[] }
  | { action: "update-exit-node"; data: ExitNode }

/**
 * POST /api/up data
 */
type TailscaleUpData = {
  Reauthenticate?: boolean // force reauthentication
  ControlURL?: string
  AuthKey?: string
}

/**
 * GET /api/auth/session/new data
 */
type AuthSessionNewData = {
  authUrl: string
}

/**
 * PATCH /api/local/v0/prefs data
 */
type LocalPrefsData = {
  RunSSHSet?: boolean
  RunSSH?: boolean
}

/**
 * POST /api/routes data
 */
type RoutesData = {
  SetExitNode?: boolean
  SetRoutes?: boolean
  UseExitNode?: string
  AdvertiseExitNode?: boolean
  AdvertiseRoutes?: string[]
}

/**
 * useAPI hook returns an api handler that can execute api calls
 * throughout the web client UI.
 */
export function useAPI() {
  const toaster = useToaster()
  const { mutate } = useSWRConfig() // allows for global mutation

  const handlePostError = useCallback(
    (toast?: string) => (err: Error) => {
      console.error(err)
      toast && toaster.show({ variant: "danger", message: toast })
      throw err
    },
    [toaster]
  )

  /**
   * optimisticMutate wraps the SWR `mutate` function to apply some
   * type-awareness with the following behavior:
   *
   *    1. `optimisticData` update is applied immediately on FetchDataType
   *       throughout the web client UI.
   *
   *    2. `fetch` data mutation runs.
   *
   *    3. On completion, FetchDataType is revalidated to exactly reflect the
   *       updated server state.
   *
   * The `key` argument is the useSWR key associated with the MutateDataType.
   * All `useSWR(key)` consumers throughout the UI will see updates reflected.
   */
  const optimisticMutate = useCallback(
    <MutateDataType, FetchDataType = any>(
      key: string,
      fetch: Promise<FetchDataType>,
      optimisticData: (current: MutateDataType) => MutateDataType,
      revalidate?: boolean // optionally specify whether to run final revalidation (step 3)
    ): Promise<FetchDataType | undefined> => {
      const options: MutatorOptions = {
        /**
         * populateCache is meant for use when the remote request returns back
         * the updated data directly. i.e. When FetchDataType is the same as
         * MutateDataType. Most of our data manipulation requests return a 200
         * with empty data on success. We turn off populateCache so that the
         * cache only gets updated after completion of the remote reqeust when
         * the revalidation step runs.
         */
        populateCache: false,
        optimisticData,
        revalidate: revalidate,
      }
      return mutate(key, fetch, options)
    },
    [mutate]
  )

  const api = useCallback(
    (t: APIType) => {
      switch (t.action) {
        /**
         * "up" handles authenticating the machine to tailnet.
         */
        case "up":
          return apiFetch<{ url?: string }>("/up", "POST", t.data)
            .then((d) => d.url && window.open(d.url, "_blank")) // "up" login step
            .then(() => incrementMetric("web_client_node_connect"))
            .then(() => mutate("/data"))
            .catch(handlePostError("Failed to login"))

        /**
         * "logout" handles logging the node out of tailscale, effectively
         * expiring its node key.
         */
        case "logout":
          // For logout, must increment metric before running api call,
          // as tailscaled will be unreachable after the call completes.
          incrementMetric("web_client_node_disconnect")
          return apiFetch("/local/v0/logout", "POST").catch(
            handlePostError("Failed to logout")
          )

        /**
         * "new-auth-session" handles creating a new check mode session to
         * authorize the viewing user to manage the node via the web client.
         */
        case "new-auth-session":
          return apiFetch<AuthSessionNewData>("/auth/session/new", "GET").catch(
            handlePostError("Failed to create new session")
          )

        /**
         * "update-prefs" handles setting the node's tailscale prefs.
         */
        case "update-prefs": {
          return optimisticMutate<NodeData>(
            "/data",
            apiFetch<LocalPrefsData>("/local/v0/prefs", "PATCH", t.data),
            (old) => ({
              ...old,
              RunningSSHServer: t.data.RunSSHSet
                ? Boolean(t.data.RunSSH)
                : old.RunningSSHServer,
            })
          )
            .then(
              () =>
                t.data.RunSSHSet &&
                incrementMetric(
                  t.data.RunSSH
                    ? "web_client_ssh_enable"
                    : "web_client_ssh_disable"
                )
            )
            .catch(handlePostError("Failed to update node preference"))
        }

        /**
         * "update-routes" handles setting the node's advertised routes.
         */
        case "update-routes": {
          const body: RoutesData = {
            SetRoutes: true,
            AdvertiseRoutes: t.data.map((r) => r.Route),
          }
          return optimisticMutate<NodeData>(
            "/data",
            apiFetch<void>("/routes", "POST", body),
            (old) => ({ ...old, AdvertisedRoutes: t.data })
          )
            .then(() => incrementMetric("web_client_advertise_routes_change"))
            .catch(handlePostError("Failed to update routes"))
        }

        /**
         * "update-exit-node" handles updating the node's state as either
         * running as an exit node or using another node as an exit node.
         */
        case "update-exit-node": {
          const id = t.data.ID
          const body: RoutesData = {
            SetExitNode: true,
          }
          if (id !== noExitNode.ID && id !== runAsExitNode.ID) {
            body.UseExitNode = id
          } else if (id === runAsExitNode.ID) {
            body.AdvertiseExitNode = true
          }
          const metrics: MetricName[] = []
          return optimisticMutate<NodeData>(
            "/data",
            apiFetch<void>("/routes", "POST", body),
            (old) => {
              // Only update metrics whose values have changed.
              if (old.AdvertisingExitNode !== Boolean(body.AdvertiseExitNode)) {
                metrics.push(
                  body.AdvertiseExitNode
                    ? "web_client_advertise_exitnode_enable"
                    : "web_client_advertise_exitnode_disable"
                )
              }
              if (Boolean(old.UsingExitNode) !== Boolean(body.UseExitNode)) {
                metrics.push(
                  body.UseExitNode
                    ? "web_client_use_exitnode_enable"
                    : "web_client_use_exitnode_disable"
                )
              }
              return {
                ...old,
                UsingExitNode: Boolean(body.UseExitNode) ? t.data : undefined,
                AdvertisingExitNode: Boolean(body.AdvertiseExitNode),
                AdvertisingExitNodeApproved: Boolean(body.AdvertiseExitNode)
                  ? true // gets updated in revalidation
                  : old.AdvertisingExitNodeApproved,
              }
            },
            false // skip final revalidation
          )
            .then(() => metrics.forEach((m) => incrementMetric(m)))
            .catch(handlePostError("Failed to update exit node"))
        }

        default:
          assertNever(t)
      }
    },
    [handlePostError, mutate, optimisticMutate]
  )

  return api
}

let csrfToken: string
let synoToken: string | undefined // required for synology API requests
let unraidCsrfToken: string | undefined // required for unraid POST requests (#8062)

/**
 * apiFetch wraps the standard JS fetch function with csrf header
 * management and param additions specific to the web client.
 *
 * apiFetch adds the `api` prefix to the request URL,
 * so endpoint should be provided without the `api` prefix
 * (i.e. provide `/data` rather than `api/data`).
 */
export function apiFetch<T>(
  endpoint: string,
  method: "GET" | "POST" | "PATCH",
  body?: any
): Promise<T> {
  const urlParams = new URLSearchParams(window.location.search)
  const nextParams = new URLSearchParams()
  if (synoToken) {
    nextParams.set("SynoToken", synoToken)
  } else {
    const token = urlParams.get("SynoToken")
    if (token) {
      nextParams.set("SynoToken", token)
    }
  }
  const search = nextParams.toString()
  const url = `api${endpoint}${search ? `?${search}` : ""}`

  var contentType: string
  if (unraidCsrfToken && method === "POST") {
    const params = new URLSearchParams()
    params.append("csrf_token", unraidCsrfToken)
    if (body) {
      params.append("ts_data", JSON.stringify(body))
    }
    body = params.toString()
    contentType = "application/x-www-form-urlencoded;charset=UTF-8"
  } else {
    body = body ? JSON.stringify(body) : undefined
    contentType = "application/json"
  }

  return fetch(url, {
    method: method,
    headers: {
      Accept: "application/json",
      "Content-Type": contentType,
      "X-CSRF-Token": csrfToken,
    },
    body: body,
  })
    .then((r) => {
      updateCsrfToken(r)
      if (!r.ok) {
        return r.text().then((err) => {
          throw new Error(err)
        })
      }
      return r
    })
    .then((r) => {
      if (r.headers.get("Content-Type") === "application/json") {
        return r.json()
      }
    })
    .then((r) => {
      r?.UnraidToken && setUnraidCsrfToken(r.UnraidToken)
      return r
    })
}

function updateCsrfToken(r: Response) {
  const tok = r.headers.get("X-CSRF-Token")
  if (tok) {
    csrfToken = tok
  }
}

export function setSynoToken(token?: string) {
  synoToken = token
}

function setUnraidCsrfToken(token?: string) {
  unraidCsrfToken = token
}

/**
 * incrementMetric hits the client metrics local API endpoint to
 * increment the given counter metric by one.
 */
export function incrementMetric(metricName: MetricName) {
  const postData: MetricsPOSTData[] = [
    {
      Name: metricName,
      Type: "counter",
      Value: 1,
    },
  ]

  apiFetch("/local/v0/upload-client-metrics", "POST", postData).catch(
    (error) => {
      console.error(error)
    }
  )
}

type MetricsPOSTData = {
  Name: MetricName
  Type: MetricType
  Value: number
}

type MetricType = "counter" | "gauge"

export type MetricName =
  | "web_client_advertise_exitnode_enable"
  | "web_client_advertise_exitnode_disable"
  | "web_client_use_exitnode_enable"
  | "web_client_use_exitnode_disable"
  | "web_client_ssh_enable"
  | "web_client_ssh_disable"
  | "web_client_node_connect"
  | "web_client_node_disconnect"
  | "web_client_advertise_routes_change"
