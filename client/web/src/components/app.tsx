import cx from "classnames"
import React from "react"
import LegacyClientView from "src/components/views/legacy-client-view"
import LoginClientView from "src/components/views/login-client-view"
import ReadonlyClientView from "src/components/views/readonly-client-view"
import useAuth from "src/hooks/auth"
import useNodeData, { UpdateProgress, UpdateState } from "src/hooks/node-data"
import ManagementClientView from "./views/management-client-view"
import { apiFetch } from "src/api"
import { useState } from "react"
import { UpdatingView } from "./views/updating-view"
import { UpdateAvailableNotification } from "src/ui/update-available"

export default function App() {
  const { data, refreshData, updateNode } = useNodeData()
  const { data: auth, loading: loadingAuth, waitOnAuth } = useAuth()

  const initialUpdateState =
    (data?.ClientVersion.RunningLatest) ? UpdateState.UpToDate : UpdateState.Available

  const [updating, setUpdating] = useState<UpdateState>(initialUpdateState)

  const [updateLog, setUpdateLog] = useState<string>('')

  const appendUpdateLog = (msg: string) => {
    console.log(msg)
    setUpdateLog(updateLog + msg + '\n')
  }

  const updatingViewStates = [
    UpdateState.InProgress, UpdateState.Complete, UpdateState.Failed
  ]

  return (
    <div className="flex flex-col items-center min-w-sm max-w-lg mx-auto py-14 align-middle h-screen">
      {!data || loadingAuth ? (
        <div className="text-center py-14">Loading...</div> // TODO(sonia): add a loading view
      ) : updatingViewStates.includes(updating) ? (
        <UpdatingView
          updating={updating}
          cv={data.ClientVersion}
          updateLog={updateLog}
        />
      ) : data?.Status === "NeedsLogin" || data?.Status === "NoState" ? (
        // Client not on a tailnet, render login.
        <LoginClientView
          data={data}
          onLoginClick={() => updateNode({ Reauthenticate: true })}
        />
      ) : data.DebugMode === "full" && auth?.ok ? (
        // Render new client interface in management mode.
        <ManagementClientView {...data} />
      ) : data.DebugMode === "login" || data.DebugMode === "full" ? (
        // Render new client interface in readonly mode.
        <>
          <ReadonlyClientView data={data} auth={auth} waitOnAuth={waitOnAuth} />
          {
            // TODO(naman): move into ReadonlyClient or ManagementClient
            data.ClientVersion.RunningLatest ? null : (
              <UpdateAvailableNotification
                currentVersion={data.IPNVersion}
                details={data.ClientVersion}
                updating={updating}
                setUpdating={setUpdating}
                appendUpdateLog={appendUpdateLog}
              />
            )
          }
        </>
      ) : (
        // Render legacy client interface.
        <LegacyClientView
          data={data}
          refreshData={refreshData}
          updateNode={updateNode}
        />
      )}
      {data && !loadingAuth && <Footer licensesURL={data.LicensesURL} />}
    </div>
  )
}

export function Footer(props: { licensesURL: string; className?: string }) {
  return (
    <footer
      className={cx("container max-w-lg mx-auto text-center", props.className)}
    >
      <a
        className="text-xs text-gray-500 hover:text-gray-600"
        href={props.licensesURL}
      >
        Open Source Licenses
      </a>
    </footer>
  )
}
