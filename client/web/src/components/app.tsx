import cx from "classnames"
import React, { useEffect } from "react"
import { ReactComponent as TailscaleIcon } from "src/assets/icons/tailscale-icon.svg"
import LoginToggle from "src/components/login-toggle"
import DeviceDetailsView from "src/components/views/device-details-view"
import HomeView from "src/components/views/home-view"
import LoginView from "src/components/views/login-view"
import SSHView from "src/components/views/ssh-view"
import { UpdatingView } from "src/components/views/updating-view"
import useAuth, { AuthResponse } from "src/hooks/auth"
import useNodeData, { NodeData } from "src/hooks/node-data"
import { Link, Route, Router, Switch, useLocation } from "wouter"

export default function App() {
  const { data: auth, loading: loadingAuth, newSession } = useAuth()

  return (
    <main className="min-w-sm max-w-lg mx-auto py-14 px-5">
      {loadingAuth || !auth ? (
        <div className="text-center py-14">Loading...</div> // TODO(sonia): add a loading view
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
  const { data, refreshData, updateNode, updatePrefs } = useNodeData()
  useEffect(() => {
    refreshData()
  }, [auth, refreshData])

  return !data ? (
    <div className="text-center py-14">Loading...</div>
  ) : data.Status === "NeedsLogin" ||
    data.Status === "NoState" ||
    data.Status === "Stopped" ? (
    // Client not on a tailnet, render login.
    <LoginView data={data} refreshData={refreshData} />
  ) : (
    // Otherwise render the new web client.
    <>
      <Router base={data.URLPrefix}>
        <Header node={data} auth={auth} newSession={newSession} />
        <Switch>
          <Route path="/">
            <HomeView
              readonly={!auth.canManageNode}
              node={data}
              updateNode={updateNode}
              updatePrefs={updatePrefs}
            />
          </Route>
          <Route path="/details">
            <DeviceDetailsView readonly={!auth.canManageNode} node={data} />
          </Route>
          <Route path="/subnets">{/* TODO */}Subnet router</Route>
          <Route path="/ssh">
            <SSHView
              readonly={!auth.canManageNode}
              runningSSH={data.RunningSSHServer}
              updatePrefs={updatePrefs}
            />
          </Route>
          <Route path="/serve">{/* TODO */}Share local content</Route>
          <Route path="/update">
            <UpdatingView
              versionInfo={data.ClientVersion}
              currentVersion={data.IPNVersion}
            />
          </Route>
          <Route>
            <h2 className="mt-8">Page not found</h2>
          </Route>
        </Switch>
      </Router>
    </>
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

  return (
    <>
      <div className="flex justify-between mb-12">
        <div className="flex gap-3">
          <TailscaleIcon />
          <div className="inline text-neutral-800 text-lg font-medium leading-snug">
            {node.DomainName}
          </div>
        </div>
        <LoginToggle node={node} auth={auth} newSession={newSession} />
      </div>
      {loc !== "/" && loc !== "/update" && (
        <Link
          to="/"
          className="text-indigo-500 font-medium leading-snug block mb-[10px]"
        >
          &larr; Back to {node.DeviceName}
        </Link>
      )}
    </>
  )
}

function Footer({
  licensesURL,
  className,
}: {
  licensesURL: string
  className?: string
}) {
  return (
    <footer className={cx("container max-w-lg mx-auto text-center", className)}>
      <a
        className="text-xs text-gray-500 hover:text-gray-600"
        href={licensesURL}
      >
        Open Source Licenses
      </a>
    </footer>
  )
}
