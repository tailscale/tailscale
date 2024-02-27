// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import TailscaleIcon from "src/assets/icons/tailscale-icon.svg?react"
import LoginToggle from "src/components/login-toggle"
import DeviceDetailsView from "src/components/views/device-details-view"
import DisconnectedView from "src/components/views/disconnected-view"
import HomeView from "src/components/views/home-view"
import LoginView from "src/components/views/login-view"
import SSHView from "src/components/views/ssh-view"
import SubnetRouterView from "src/components/views/subnet-router-view"
import { UpdatingView } from "src/components/views/updating-view"
import useAuth, { AuthResponse, canEdit } from "src/hooks/auth"
import { Feature, NodeData, featureDescription } from "src/types"
import Card from "src/ui/card"
import EmptyState from "src/ui/empty-state"
import LoadingDots from "src/ui/loading-dots"
import useSWR from "swr"
import { Link, Route, Router, Switch, useLocation } from "wouter"

export default function App() {
  const { data: auth, loading: loadingAuth, newSession } = useAuth()

  return (
    <main className="min-w-sm max-w-lg mx-auto py-4 sm:py-14 px-5">
      {loadingAuth || !auth ? (
        <LoadingView />
      ) : (
        <WebClient auth={auth} newSession={newSession} />
      )}
    </main>
  )
}

function WebClient({
  auth,
  newSession,
}: {
  auth: AuthResponse
  newSession: () => Promise<void>
}) {
  const { data: node } = useSWR<NodeData>("/data")

  return !node ? (
    <LoadingView />
  ) : node.Status === "NeedsLogin" ||
    node.Status === "NoState" ||
    node.Status === "Stopped" ? (
    // Client not on a tailnet, render login.
    <LoginView data={node} />
  ) : (
    // Otherwise render the new web client.
    <>
      <Router base={node.URLPrefix}>
        <Header node={node} auth={auth} newSession={newSession} />
        <Switch>
          <Route path="/">
            <HomeView node={node} auth={auth} />
          </Route>
          <Route path="/details">
            <DeviceDetailsView node={node} auth={auth} />
          </Route>
          <FeatureRoute path="/subnets" feature="advertise-routes" node={node}>
            <SubnetRouterView
              readonly={!canEdit("subnets", auth)}
              node={node}
            />
          </FeatureRoute>
          <FeatureRoute path="/ssh" feature="ssh" node={node}>
            <SSHView readonly={!canEdit("ssh", auth)} node={node} />
          </FeatureRoute>
          {/* <Route path="/serve">Share local content</Route> */}
          <FeatureRoute path="/update" feature="auto-update" node={node}>
            <UpdatingView
              versionInfo={node.ClientVersion}
              currentVersion={node.IPNVersion}
            />
          </FeatureRoute>
          <Route path="/disconnected">
            <DisconnectedView />
          </Route>
          <Route>
            <Card className="mt-8">
              <EmptyState description="Page not found" />
            </Card>
          </Route>
        </Switch>
      </Router>
    </>
  )
}

/**
 * FeatureRoute renders a Route component,
 * but only displays the child view if the specified feature is
 * available for use on this node's platform. If not available,
 * a not allowed view is rendered instead.
 */
function FeatureRoute({
  path,
  node,
  feature,
  children,
}: {
  path: string
  node: NodeData
  feature: Feature
  children: React.ReactNode
}) {
  return (
    <Route path={path}>
      {!node.Features[feature] ? (
        <Card className="mt-8">
          <EmptyState
            description={`${featureDescription(
              feature
            )} not available on this device.`}
          />
        </Card>
      ) : (
        children
      )}
    </Route>
  )
}

function Header({
  node,
  auth,
  newSession,
}: {
  node: NodeData
  auth: AuthResponse
  newSession: () => Promise<void>
}) {
  const [loc] = useLocation()

  if (loc === "/disconnected") {
    // No header on view presented after logout.
    return null
  }

  return (
    <>
      <div className="flex flex-wrap gap-4 justify-between items-center mb-9 md:mb-12">
        <Link to="/" className="flex gap-3 overflow-hidden">
          <TailscaleIcon />
          <div className="inline text-gray-800 text-lg font-medium leading-snug truncate">
            {node.DomainName}
          </div>
        </Link>
        <LoginToggle node={node} auth={auth} newSession={newSession} />
      </div>
      {loc !== "/" && loc !== "/update" && (
        <Link to="/" className="link font-medium block mb-2">
          &larr; Back to {node.DeviceName}
        </Link>
      )}
    </>
  )
}

/**
 * LoadingView fills its container with small animated loading dots
 * in the center.
 */
export function LoadingView() {
  return (
    <LoadingDots className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
  )
}
